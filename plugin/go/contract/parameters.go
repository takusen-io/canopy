package contract

import (
	"bytes"
	"encoding/base64"
	"math"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
)

// AWS Nitro Enclaves Root-G1 DER.
const defaultNitroTrustRootBase64 = "MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYDVQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEGBSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZEh8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYCMQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPWrfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6NIwLz3/Y="

const (
	maxFoundationFeeBps  uint32 = 1_000_000
	maxServicerMarginBps uint32 = 10_000
)

const (
	minimumDomainAbandonmentDelaySeconds uint64 = 24 * 60 * 60
	defaultDomainAbandonmentDelaySeconds uint64 = 7 * 24 * 60 * 60
	maximumGovernanceIntentSeconds       uint64 = 7 * 24 * 60 * 60
)

const (
	domainStateStaged      = "STAGED"
	domainStateActive      = "ACTIVE"
	domainStateDeactivated = "DEACTIVATED"
	domainStateResolved    = "RESOLVED"
)

func defaultProtocolParams() *ProtocolParams {
	nitroRoot, _ := base64.StdEncoding.DecodeString(defaultNitroTrustRootBase64)
	return &ProtocolParams{
		MinimumServicerBond: 1, ServicerUnbondingBlocks: 86_400,
		InvalidReceiptSlashBps: 100, TreasuryAddress: bytes.Repeat([]byte{0x77}, 20),
		BridgeEpochMintLimit: math.MaxUint64, BridgeTransferLimit: math.MaxUint64,
		MinimumBridgeAmount:    1,
		SupportedOutputSchemas: []string{"boolean", "score", "choice", "private_hash"},
		SettlementDomains:      []*SettlementDomain{defaultSettlementDomain()},
		NitroTrustRoots:        [][]byte{nitroRoot},
	}
}

func defaultSettlementDomain() *SettlementDomain {
	token := bytes.Repeat([]byte{0x44}, 20)
	escrow := bytes.Repeat([]byte{0x55}, 20)
	verifier := bytes.Repeat([]byte{0x66}, 20)
	governance := bytes.Repeat([]byte{0x88}, 20)
	return &SettlementDomain{
		Id:      keccak(abiUint64(8453), abiAddress(token), abiAddress(escrow), abiAddress(verifier)),
		ChainId: 8453, TokenAddress: token, EscrowAddress: escrow, VerifierAddress: verifier,
		FoundationTreasuryAddress: bytes.Repeat([]byte{0x77}, 20), TokenDecimals: 6,
		Network: "eip155:8453", DepositMechanisms: []string{"eip3009"}, FinalityPolicy: "safe", State: domainStateActive,
		AuthorizationName: "USD Coin", AuthorizationVersion: "2",
		AbandonmentDelaySeconds: defaultDomainAbandonmentDelaySeconds, GovernanceAddress: governance,
	}
}

func (c *Contract) currentProtocolParams() (*ProtocolParams, *PluginError) {
	params := new(ProtocolParams)
	found, err := c.read(KeyForProtocolParams(), params)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrState("governed protocol parameters are missing")
	}
	return params, nil
}

func validateProtocolParams(params *ProtocolParams) *PluginError {
	if params == nil || params.Revision == 0 ||
		params.FoundationFeeBps > maxFoundationFeeBps || params.ServicerMarginBps > maxServicerMarginBps ||
		(params.ServicerMarginBps > 0 && params.ServicerMarginBps >= params.FoundationFeeBps) ||
		params.InvalidReceiptSlashBps > 10_000 || params.TreasuryBps > 10_000 ||
		params.ServicerUnbondingBlocks == 0 || params.ServicerUnbondingBlocks <= params.AuthorizationDeadlineBlocks ||
		params.MinimumServicerBond == 0 || params.MinimumBridgeAmount == 0 || params.BridgeTransferLimit < params.MinimumBridgeAmount {
		return ErrInvalidTransaction("invalid governed protocol parameters")
	}
	if params.CanonicalChainId != 0 || len(params.CanonicalTokenAddress) != 0 || len(params.CanonicalBridgeAddress) != 0 || params.EmissionPerEpoch != 0 {
		if params.CanonicalChainId == 0 || !validAddress(params.CanonicalTokenAddress) || !validAddress(params.CanonicalBridgeAddress) ||
			!validAddress(params.TreasuryAddress) {
			return ErrInvalidTransaction("canonical reward and bridge parameters are incomplete")
		}
	}
	seenDomains := make(map[string]struct{}, len(params.SettlementDomains))
	for _, domain := range params.SettlementDomains {
		if err := validateSettlementDomain(domain); err != nil {
			return err
		}
		key := string(domain.Id)
		if _, duplicate := seenDomains[key]; duplicate {
			return ErrInvalidTransaction("duplicate governed settlement domain")
		}
		seenDomains[key] = struct{}{}
	}
	models := make(map[string]bool, len(params.Models))
	for _, model := range params.Models {
		if model == nil || model.Model == "" || model.Provider == "" || len(model.Model) > 200 || len(model.Provider) > 100 ||
			model.MinimumExecutionBudget == 0 || model.MaximumExecutionBudget < model.MinimumExecutionBudget ||
			model.InputPriceMicrosPerMillionTokens == 0 || model.OutputPriceMicrosPerMillionTokens == 0 {
			return ErrInvalidTransaction("invalid governed model")
		}
		if _, exists := models[model.Model]; exists {
			return ErrInvalidTransaction("duplicate governed model")
		}
		models[model.Model] = model.Active
	}
	schemas := make(map[string]struct{}, len(params.SupportedOutputSchemas))
	for _, schema := range params.SupportedOutputSchemas {
		switch schema {
		case "boolean", "score", "choice", "private_hash":
		default:
			return ErrInvalidTransaction("unsupported governed output schema")
		}
		if _, exists := schemas[schema]; exists {
			return ErrInvalidTransaction("duplicate governed output schema")
		}
		schemas[schema] = struct{}{}
	}
	if len(params.SupportedOutputSchemas) == 0 {
		return ErrInvalidTransaction("at least one governed output schema is required")
	}
	defaults := make(map[string]struct{}, len(params.DefaultModels))
	for _, model := range params.DefaultModels {
		if !models[model] {
			return ErrInvalidTransaction("default model must be active in governance")
		}
		if _, exists := defaults[model]; exists {
			return ErrInvalidTransaction("duplicate governed default model")
		}
		defaults[model] = struct{}{}
	}
	if len(params.Models) > 0 && len(params.DefaultModels) == 0 {
		return ErrInvalidTransaction("at least one governed default model is required")
	}
	activePCRs := 0
	seenPCRs := make(map[string]struct{}, len(params.ApprovedPcrs))
	for _, policy := range params.ApprovedPcrs {
		if policy == nil || !validPCRMeasurements(policy.Pcr0, policy.Pcr1, policy.Pcr2) {
			return ErrInvalidTransaction("invalid governed PCR policy")
		}
		identity := string(policy.Pcr0) + string(policy.Pcr1) + string(policy.Pcr2)
		if _, duplicate := seenPCRs[identity]; duplicate {
			return ErrInvalidTransaction("duplicate governed PCR policy")
		}
		seenPCRs[identity] = struct{}{}
		if policy.Active {
			activePCRs++
		}
	}
	if activePCRs == 0 {
		return ErrInvalidTransaction("at least one active governed PCR policy is required")
	}
	if _, rootErr := parseNitroTrustRoots(params.NitroTrustRoots); rootErr != nil {
		return ErrInvalidTransaction("one to eight unique governed Nitro trust roots are required")
	}
	return nil
}

func validateSettlementDomain(domain *SettlementDomain) *PluginError {
	if domain == nil || len(domain.Id) != 32 || domain.ChainId == 0 ||
		!validAddress(domain.TokenAddress) || !validAddress(domain.EscrowAddress) ||
		!validAddress(domain.VerifierAddress) || !validAddress(domain.FoundationTreasuryAddress) || !validAddress(domain.GovernanceAddress) ||
		domain.TokenDecimals < 6 || domain.TokenDecimals > 36 || domain.Network != "eip155:"+strconv.FormatUint(domain.ChainId, 10) ||
		len(domain.DepositMechanisms) == 0 || domain.AbandonmentDelaySeconds < minimumDomainAbandonmentDelaySeconds {
		return ErrInvalidTransaction("invalid governed settlement domain")
	}
	switch domain.State {
	case domainStateStaged, domainStateActive, domainStateDeactivated, domainStateResolved:
	default:
		return ErrInvalidTransaction("invalid governed settlement-domain state")
	}
	expected := keccak(
		abiUint64(domain.ChainId), abiAddress(domain.TokenAddress),
		abiAddress(domain.EscrowAddress), abiAddress(domain.VerifierAddress),
	)
	if !bytes.Equal(domain.Id, expected) {
		return ErrInvalidTransaction("settlement domain identifier does not match its contracts")
	}
	mechanisms := make(map[string]struct{}, len(domain.DepositMechanisms))
	hasEIP3009 := false
	for _, mechanism := range domain.DepositMechanisms {
		switch mechanism {
		case "eip3009":
			hasEIP3009 = true
		case "approve":
		default:
			return ErrInvalidTransaction("unsupported settlement deposit mechanism")
		}
		if _, duplicate := mechanisms[mechanism]; duplicate {
			return ErrInvalidTransaction("duplicate settlement deposit mechanism")
		}
		mechanisms[mechanism] = struct{}{}
	}
	if hasEIP3009 && (strings.TrimSpace(domain.AuthorizationName) == "" || strings.TrimSpace(domain.AuthorizationVersion) == "") {
		return ErrInvalidTransaction("EIP-3009 settlement domains require an authorization name and version")
	}
	switch domain.FinalityPolicy {
	case "safe", "finalized", "confirmed", "flashblock":
	default:
		return ErrInvalidTransaction("unsupported settlement finality policy")
	}
	return nil
}

func settlementDomain(params *ProtocolParams, id []byte, requireActive bool) (*SettlementDomain, *PluginError) {
	if len(id) != 32 {
		return nil, ErrInvalidTransaction("settlement domain identifier is required")
	}
	for _, domain := range params.SettlementDomains {
		if bytes.Equal(domain.Id, id) {
			if requireActive && domain.State != domainStateActive {
				return nil, ErrUnauthorized("settlement domain is inactive")
			}
			return domain, nil
		}
	}
	return nil, ErrNotFound("settlement domain is not governed")
}

func (c *Contract) deliverGovernedParameter(space, key string, value []byte) *PluginDeliverResponse {
	if space != "takusen" || len(value) == 0 {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("unsupported governed plugin parameter")}
	}
	switch key {
	case "protocolParams":
		return c.deliverGovernedProtocolParams(value)
	case "settlementDomainAction":
		return c.deliverGovernedSettlementDomainAction(value)
	case "evmGovernanceActionIntent":
		return c.deliverGovernedEVMActionIntent(value)
	default:
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("unsupported governed plugin parameter")}
	}
}

func decodeGovernedValue(value []byte, destination proto.Message) *PluginError {
	encoded, decodeErr := base64.StdEncoding.DecodeString(string(value))
	if decodeErr != nil {
		return ErrInvalidTransaction("governed value is not canonical base64")
	}
	return Unmarshal(encoded, destination)
}

func (c *Contract) deliverGovernedProtocolParams(value []byte) *PluginDeliverResponse {
	params := new(ProtocolParams)
	if err := decodeGovernedValue(value, params); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if err := validateProtocolParams(params); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	current, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if params.Revision != current.Revision+1 {
		return &PluginDeliverResponse{Error: ErrConflict("protocol parameter revision must increase by one")}
	}
	if !sameSettlementDomains(params.SettlementDomains, current.SettlementDomains) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("settlement domains change only through typed domain governance")}
	}
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{
		string(KeyForProtocolParams()): params,
	})}
}

func sameSettlementDomains(left, right []*SettlementDomain) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !proto.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

func settlementDomainActionID(action *SettlementDomainAction) ([]byte, *PluginError) {
	var encodedDomain []byte
	var err *PluginError
	if action.Domain != nil {
		encodedDomain, err = Marshal(action.Domain)
		if err != nil {
			return nil, err
		}
	}
	return hashFields(
		[]byte("takusen:settlement-domain-action:v1"), []byte(action.Action), action.SettlementDomainId,
		encodedDomain, action.DeactivationGeneration, uint64Bytes(action.Nonce), uint64Bytes(action.ExpectedRevision),
		uint64Bytes(action.ExpiresAtTimestamp), []byte(action.Resolution),
	), nil
}

func (c *Contract) deliverGovernedSettlementDomainAction(value []byte) *PluginDeliverResponse {
	action := new(SettlementDomainAction)
	if err := decodeGovernedValue(value, action); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if len(action.SettlementDomainId) != 32 || action.Nonce == 0 || action.ExpectedRevision == 0 ||
		(action.Action != "register" && action.Action != "activate" && action.Action != "deactivate" && action.Action != "reactivate" && action.Action != "resolve") {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid settlement-domain action")}
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if action.ExpectedRevision != params.Revision {
		return &PluginDeliverResponse{Error: ErrConflict("settlement-domain action uses a stale protocol revision")}
	}
	clock, err := c.currentEpochClock(params)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if clock.ConsensusTimeSeconds == 0 || action.ExpiresAtTimestamp <= clock.ConsensusTimeSeconds ||
		action.ExpiresAtTimestamp-clock.ConsensusTimeSeconds > maximumGovernanceIntentSeconds {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("settlement-domain action expiry must be within seven days")}
	}
	prior := new(SettlementDomainAction)
	foundPrior, readErr := c.read(KeyForSettlementDomainAction(action.SettlementDomainId), prior)
	if readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	}
	if (foundPrior && action.Nonce != prior.Nonce+1) || (!foundPrior && action.Nonce != 1) {
		return &PluginDeliverResponse{Error: ErrConflict("settlement-domain action nonce must increase by one")}
	}
	expectedID, idErr := settlementDomainActionID(action)
	if idErr != nil || !bytes.Equal(action.Id, expectedID) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("settlement-domain action identifier does not match its governed fields")}
	}
	next := proto.Clone(params).(*ProtocolParams)
	next.Revision++
	records := map[string]proto.Message{string(KeyForSettlementDomainAction(action.SettlementDomainId)): action}
	var deletes [][]byte
	domainIndex := -1
	for index, domain := range next.SettlementDomains {
		if domain != nil && bytes.Equal(domain.Id, action.SettlementDomainId) {
			domainIndex = index
			break
		}
	}
	preparedHandoff := clock.ValidatorRosterFrozen || clock.ValidatorHandoffPrepared || clock.ValidatorHandoffTimestamp != 0
	switch action.Action {
	case "register":
		if domainIndex >= 0 || action.Domain == nil || !bytes.Equal(action.Domain.Id, action.SettlementDomainId) ||
			(action.Domain.State != domainStateStaged && action.Domain.State != domainStateActive) {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid settlement-domain registration")}
		}
		if validationErr := validateSettlementDomain(action.Domain); validationErr != nil {
			return &PluginDeliverResponse{Error: validationErr}
		}
		if found, markerErr := c.read(KeyForSettlementDomainResolution(action.SettlementDomainId), new(SettlementDomainResolution)); markerErr != nil {
			return &PluginDeliverResponse{Error: markerErr}
		} else if found {
			return &PluginDeliverResponse{Error: ErrUnauthorized("resolved settlement domains cannot be readmitted")}
		}
		if found, authorityErr := c.read(KeyForSettlementDomainAuthority(action.SettlementDomainId, clock.ValidatorSetId), new(ReplayMarker)); authorityErr != nil {
			return &PluginDeliverResponse{Error: authorityErr}
		} else if !found {
			return &PluginDeliverResponse{Error: ErrUnauthorized("settlement-domain registration lacks current finalized authority")}
		}
		if action.Domain.State == domainStateActive && preparedHandoff {
			return &PluginDeliverResponse{Error: ErrConflict("an active domain cannot join during a prepared validator handoff")}
		}
		next.SettlementDomains = append(next.SettlementDomains, proto.Clone(action.Domain).(*SettlementDomain))
	case "activate":
		if domainIndex < 0 || next.SettlementDomains[domainIndex].State != domainStateStaged || preparedHandoff {
			return &PluginDeliverResponse{Error: ErrConflict("only a staged domain outside handoff may activate")}
		}
		if found, authorityErr := c.read(KeyForSettlementDomainAuthority(action.SettlementDomainId, clock.ValidatorSetId), new(ReplayMarker)); authorityErr != nil {
			return &PluginDeliverResponse{Error: authorityErr}
		} else if !found {
			return &PluginDeliverResponse{Error: ErrUnauthorized("settlement-domain activation lacks current finalized authority")}
		}
		next.SettlementDomains[domainIndex].State = domainStateActive
	case "deactivate":
		if domainIndex < 0 || next.SettlementDomains[domainIndex].State != domainStateActive {
			return &PluginDeliverResponse{Error: ErrConflict("only an active settlement domain may deactivate")}
		}
		domain := next.SettlementDomains[domainIndex]
		domain.State = domainStateDeactivated
		generation := settlementDomainDeactivationGeneration(domain.Id, next.Revision, clock.ConsensusTimeSeconds)
		records[string(KeyForSettlementDomainDeactivation(domain.Id))] = &SettlementDomainDeactivationSnapshot{
			SettlementDomainId: append([]byte(nil), domain.Id...), Generation: generation,
			Timestamp: clock.ConsensusTimeSeconds, AbandonmentDelaySeconds: domain.AbandonmentDelaySeconds,
		}
	case "reactivate":
		if domainIndex < 0 || next.SettlementDomains[domainIndex].State != domainStateDeactivated || preparedHandoff {
			return &PluginDeliverResponse{Error: ErrConflict("only a deactivated domain outside handoff may reactivate")}
		}
		deactivation := new(SettlementDomainDeactivationSnapshot)
		if found, deactivationErr := c.read(KeyForSettlementDomainDeactivation(action.SettlementDomainId), deactivation); deactivationErr != nil || !found ||
			!bytes.Equal(deactivation.Generation, action.DeactivationGeneration) {
			return &PluginDeliverResponse{Error: ErrConflict("reactivation does not match the current deactivation generation")}
		}
		if found, authorityErr := c.read(KeyForSettlementDomainAuthority(action.SettlementDomainId, clock.ValidatorSetId), new(ReplayMarker)); authorityErr != nil {
			return &PluginDeliverResponse{Error: authorityErr}
		} else if !found {
			return &PluginDeliverResponse{Error: ErrUnauthorized("settlement-domain reactivation lacks current finalized authority")}
		}
		pending, pendingErr := c.read(KeyForNativeAuthorizationIntent("settlement-domain-retirement-readiness", action.SettlementDomainId), new(QuorumProof))
		if pendingErr != nil {
			return &PluginDeliverResponse{Error: pendingErr}
		}
		if pending {
			if cancelled, cancelErr := c.read(KeyForSettlementDomainRetirementCancellation(action.SettlementDomainId, deactivation.Generation), new(ReplayMarker)); cancelErr != nil {
				return &PluginDeliverResponse{Error: cancelErr}
			} else if !cancelled {
				break
			}
		}
		next.SettlementDomains[domainIndex].State = domainStateActive
		deletes = append(deletes, KeyForSettlementDomainDeactivation(action.SettlementDomainId), KeyForSettlementDomainRetirementCancellation(action.SettlementDomainId, deactivation.Generation))
	case "resolve":
		if domainIndex < 0 || (action.Resolution != "clean" && action.Resolution != "abandon") {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("resolution requires a governed domain and an explicit outcome")}
		}
		if next.SettlementDomains[domainIndex].State == domainStateStaged {
			if action.Resolution != "clean" || len(action.DeactivationGeneration) != 0 {
				return &PluginDeliverResponse{Error: ErrInvalidTransaction("a never-active staged domain may only resolve cleanly")}
			}
			next.SettlementDomains[domainIndex].State = domainStateResolved
			records[string(KeyForSettlementDomainResolution(action.SettlementDomainId))] = &SettlementDomainResolution{
				SettlementDomainId: append([]byte(nil), action.SettlementDomainId...), Outcome: "DISCARDED",
				GovernanceActionId: append([]byte(nil), action.Id...), ProofId: append([]byte(nil), action.Id...),
				CompletedTimestamp: clock.ConsensusTimeSeconds,
			}
			break
		}
		if next.SettlementDomains[domainIndex].State != domainStateDeactivated {
			return &PluginDeliverResponse{Error: ErrConflict("only a staged or deactivated domain may resolve")}
		}
		deactivation := new(SettlementDomainDeactivationSnapshot)
		if found, deactivationErr := c.read(KeyForSettlementDomainDeactivation(action.SettlementDomainId), deactivation); deactivationErr != nil || !found ||
			!bytes.Equal(deactivation.Generation, action.DeactivationGeneration) {
			return &PluginDeliverResponse{Error: ErrConflict("resolution does not match the current deactivation generation")}
		}
	}
	if validationErr := validateProtocolParams(next); validationErr != nil {
		return &PluginDeliverResponse{Error: validationErr}
	}
	records[string(KeyForProtocolParams())] = next
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

func evmGovernanceActionDigest(domain *SettlementDomain, intent *EVMGovernanceActionIntent) []byte {
	typeHash := ethereumKeccak256([]byte("GovernanceAction(uint256 chainId,address governance,uint64 validatorSetId,uint64 nonce,address target,uint256 value,bytes32 dataHash)"))
	encoded := append([]byte(nil), typeHash...)
	encoded = append(encoded, abiUint64(domain.ChainId)...)
	encoded = append(encoded, abiAddress(domain.GovernanceAddress)...)
	encoded = append(encoded, abiUint64(intent.ValidatorSetId)...)
	encoded = append(encoded, abiUint64(intent.ActionNonce)...)
	encoded = append(encoded, abiAddress(intent.Target)...)
	encoded = append(encoded, intent.Value...)
	encoded = append(encoded, intent.DataHash...)
	return ethereumKeccak256(encoded)
}

func evmGovernanceActionIntentID(intent *EVMGovernanceActionIntent) []byte {
	return hashFields(
		[]byte("takusen:evm-governance-action-intent:v1"), intent.SettlementDomainId, uint64Bytes(intent.ValidatorSetId),
		uint64Bytes(intent.ActionNonce), intent.Target, intent.Value, intent.DataHash, uint64Bytes(intent.ExpiresAtTimestamp), intent.Digest,
	)
}

func (c *Contract) deliverGovernedEVMActionIntent(value []byte) *PluginDeliverResponse {
	intent := new(EVMGovernanceActionIntent)
	if err := decodeGovernedValue(value, intent); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	domain, domainErr := settlementDomain(params, intent.SettlementDomainId, false)
	clock, clockErr := c.currentEpochClock(params)
	if domainErr != nil || domain.State == domainStateResolved || clockErr != nil || intent.ValidatorSetId != clock.ValidatorSetId ||
		intent.ActionNonce == 0 || !validAddress(intent.Target) || len(intent.Value) != 32 || len(intent.DataHash) != 32 || len(intent.Digest) != 32 {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid governed EVM action intent")}
	}
	if clock.ConsensusTimeSeconds == 0 || intent.ExpiresAtTimestamp <= clock.ConsensusTimeSeconds ||
		intent.ExpiresAtTimestamp-clock.ConsensusTimeSeconds > maximumGovernanceIntentSeconds {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("governed EVM action expiry must be within seven days")}
	}
	if !bytes.Equal(intent.Digest, evmGovernanceActionDigest(domain, intent)) || !bytes.Equal(intent.Id, evmGovernanceActionIntentID(intent)) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("governed EVM action digest or identifier is invalid")}
	}
	prior := new(EVMGovernanceActionIntent)
	if found, readErr := c.read(KeyForEVMGovernanceActionIntent(intent.SettlementDomainId), prior); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found && prior.ExpiresAtTimestamp >= clock.ConsensusTimeSeconds {
		proofID := quorumProofID("governance-action", prior.ValidatorSetId, prior.Digest)
		if finalized, proofErr := c.read(KeyForQuorumProof(proofID), new(QuorumProof)); proofErr != nil {
			return &PluginDeliverResponse{Error: proofErr}
		} else if !finalized {
			return &PluginDeliverResponse{Error: ErrConflict("an unfinalized governed EVM action already exists for this domain")}
		}
	}
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{
		string(KeyForEVMGovernanceActionIntent(intent.SettlementDomainId)): intent,
	})}
}

func settlementDomainDeactivationGeneration(domainID []byte, revision, timestamp uint64) []byte {
	return hashFields(
		[]byte("takusen:settlement-domain-deactivation"), domainID, uint64Bytes(revision), uint64Bytes(timestamp),
	)
}

func modelPolicy(params *ProtocolParams, model string) *ModelParams {
	for _, candidate := range params.Models {
		if candidate.Model == model && candidate.Active {
			return candidate
		}
	}
	return nil
}

func outputSchemaEnabled(params *ProtocolParams, schema string) bool {
	for _, candidate := range params.SupportedOutputSchemas {
		if candidate == schema {
			return true
		}
	}
	return false
}

func pcrApproved(params *ProtocolParams, pcr0, pcr1, pcr2 []byte) bool {
	if params == nil || !validPCRMeasurements(pcr0, pcr1, pcr2) {
		return false
	}
	for _, policy := range params.ApprovedPcrs {
		if policy != nil && policy.Active && validPCRMeasurements(policy.Pcr0, policy.Pcr1, policy.Pcr2) && bytes.Equal(policy.Pcr0, pcr0) && bytes.Equal(policy.Pcr1, pcr1) && bytes.Equal(policy.Pcr2, pcr2) {
			return true
		}
	}
	return false
}

func validPCRMeasurements(pcr0, pcr1, pcr2 []byte) bool {
	return nonzeroPCRBank(pcr0) && nonzeroPCRBank(pcr1) && nonzeroPCRBank(pcr2)
}

func nonzeroPCRBank(value []byte) bool {
	if len(value) != 48 {
		return false
	}
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined != 0
}
