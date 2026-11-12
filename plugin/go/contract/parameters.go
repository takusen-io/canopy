package contract

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"math"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
)

func defaultProtocolParams() *ProtocolParams {
	return &ProtocolParams{
		QuorumNumerator: 2, QuorumDenominator: 3,
		RetryLimit: 3, MinimumServicerBond: 1, MinimumValidatorBond: 1,
		EpochBlocks: 3600, ValidatorHandoffNoticeSeconds: 2400, UnbondingEpochs: 24,
		BridgeEpochMintLimit: math.MaxUint64, BridgeTransferLimit: math.MaxUint64,
		SupportedOutputSchemas:  []string{"boolean", "score", "choice", "private_hash"},
		SettlementDomains:       []*SettlementDomain{defaultSettlementDomain()},
		RequireNitroAttestation: true,
	}
}

func defaultSettlementDomain() *SettlementDomain {
	token := bytes.Repeat([]byte{0x44}, 20)
	escrow := bytes.Repeat([]byte{0x55}, 20)
	verifier := bytes.Repeat([]byte{0x66}, 20)
	return &SettlementDomain{
		Id:      keccak(abiUint64(8453), abiAddress(token), abiAddress(escrow), abiAddress(verifier)),
		ChainId: 8453, TokenAddress: token, EscrowAddress: escrow, VerifierAddress: verifier,
		FoundationTreasuryAddress: bytes.Repeat([]byte{0x77}, 20), TokenDecimals: 6,
		Network: "eip155:8453", DepositMechanisms: []string{"eip3009"}, FinalityPolicy: "safe", Active: true,
		AuthorizationName: "USD Coin", AuthorizationVersion: "2",
	}
}

func (c *Contract) currentProtocolParams() (*ProtocolParams, *PluginError) {
	params := new(ProtocolParams)
	found, err := c.read(KeyForProtocolParams(), params)
	if err != nil {
		return nil, err
	}
	if !found {
		return defaultProtocolParams(), nil
	}
	return params, nil
}

func validateProtocolParams(params *ProtocolParams) *PluginError {
	if params == nil || params.Revision == 0 || params.QuorumDenominator == 0 ||
		params.QuorumNumerator >= params.QuorumDenominator ||
		uint64(params.QuorumNumerator)*3 < uint64(params.QuorumDenominator)*2 ||
		params.FoundationFeeBps > 10_000 || (params.ServicerMarginBps > 0 && params.ServicerMarginBps >= params.FoundationFeeBps) ||
		params.TimeoutSlashBps > 10_000 || params.InvalidReceiptSlashBps > 10_000 ||
		params.TreasuryBps > 10_000 || params.EpochBlocks == 0 || params.UnbondingEpochs == 0 ||
		params.ValidatorHandoffNoticeSeconds < 1200 || params.ValidatorHandoffNoticeSeconds > 7*24*60*60 ||
		params.RetryLimit == 0 || params.MinimumServicerBond == 0 || params.MinimumValidatorBond == 0 {
		return ErrInvalidTransaction("invalid governed protocol parameters")
	}
	if params.CanonicalChainId != 0 || len(params.CanonicalTokenAddress) != 0 || len(params.CanonicalBridgeAddress) != 0 || params.EmissionPerEpoch != 0 {
		if params.CanonicalChainId == 0 || !validAddress(params.CanonicalTokenAddress) || !validAddress(params.CanonicalBridgeAddress) ||
			params.ValidatorSetId == 0 || !validAddress(params.TreasuryAddress) {
			return ErrInvalidTransaction("canonical reward and bridge parameters are incomplete")
		}
	}
	activeDomains := 0
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
		if domain.Active {
			activeDomains++
		}
	}
	if activeDomains == 0 {
		return ErrInvalidTransaction("at least one active settlement domain is required")
	}
	models := make(map[string]bool, len(params.Models))
	for _, model := range params.Models {
		if model == nil || model.Model == "" || model.Provider == "" || len(model.Model) > 200 || len(model.Provider) > 100 {
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
	return nil
}

func validateSettlementDomain(domain *SettlementDomain) *PluginError {
	if domain == nil || len(domain.Id) != 32 || domain.ChainId == 0 ||
		!validAddress(domain.TokenAddress) || !validAddress(domain.EscrowAddress) ||
		!validAddress(domain.VerifierAddress) || !validAddress(domain.FoundationTreasuryAddress) ||
		domain.TokenDecimals < 6 || domain.TokenDecimals > 36 || domain.Network != "eip155:"+strconv.FormatUint(domain.ChainId, 10) ||
		len(domain.DepositMechanisms) == 0 {
		return ErrInvalidTransaction("invalid governed settlement domain")
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
			if requireActive && !domain.Active {
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
	if key == "settlementDomainLifecycleIntent" {
		return c.deliverGovernedSettlementDomainLifecycleIntent(value)
	}
	if key != "protocolParams" {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("unsupported governed plugin parameter")}
	}
	encoded, decodeErr := base64.StdEncoding.DecodeString(string(value))
	if decodeErr != nil {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("governed protocol parameters are not canonical base64")}
	}
	params := new(ProtocolParams)
	if err := Unmarshal(encoded, params); err != nil {
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
	if params.ValidatorSetId != current.ValidatorSetId {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("validator set identifiers advance only at epoch handoff")}
	}
	currentDomains := make(map[string]*SettlementDomain, len(current.SettlementDomains))
	for _, domain := range current.SettlementDomains {
		currentDomains[string(domain.Id)] = domain
	}
	authorityMembershipChanged, activatesDomain, deactivatesDomain, removesDomain := false, false, false, false
	records := map[string]proto.Message{
		string(KeyForProtocolParams()): proto.Clone(params).(*ProtocolParams),
	}
	var deletes [][]byte
	clock, clockErr := c.currentEpochClock(current)
	if clockErr != nil {
		return &PluginDeliverResponse{Error: clockErr}
	}
	for _, domain := range params.SettlementDomains {
		prior, exists := currentDomains[string(domain.Id)]
		if !exists {
			authorityMembershipChanged = true
			if found, readErr := c.read(KeyForSettlementDomainRetirement(domain.Id), new(ReplayMarker)); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if found {
				return &PluginDeliverResponse{Error: ErrUnauthorized("retired settlement domain identifiers cannot be re-admitted")}
			}
			if domain.Active {
				return &PluginDeliverResponse{Error: ErrInvalidTransaction("new settlement domains must enter governance inactive")}
			}
			if found, readErr := c.read(KeyForSettlementDomainAuthority(domain.Id, current.ValidatorSetId), new(ReplayMarker)); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if !found {
				return &PluginDeliverResponse{Error: ErrUnauthorized("new settlement domain lacks quorum-certified finalized validator authority")}
			}
			continue
		}
		if !prior.Active && domain.Active {
			activatesDomain = true
			deactivation := new(ReplayMarker)
			if found, readErr := c.read(KeyForSettlementDomainDeactivation(domain.Id), deactivation); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if found {
				if len(deactivation.Id) != 32 {
					return &PluginDeliverResponse{Error: ErrState("settlement domain has an invalid deactivation generation")}
				}
				if cancelled, cancelErr := c.read(KeyForSettlementDomainRetirementCancellation(domain.Id, deactivation.Id), new(ReplayMarker)); cancelErr != nil {
					return &PluginDeliverResponse{Error: cancelErr}
				} else if !cancelled {
					return &PluginDeliverResponse{Error: ErrUnauthorized("settlement domain reactivation requires finalized retirement-proof cancellation")}
				}
				deletes = append(
					deletes,
					KeyForSettlementDomainDeactivation(domain.Id),
					KeyForSettlementDomainDeactivationEpoch(domain.Id),
					KeyForSettlementDomainRetirementCancellation(domain.Id, deactivation.Id),
				)
			}
			if found, readErr := c.read(KeyForSettlementDomainAuthority(domain.Id, current.ValidatorSetId), new(ReplayMarker)); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if !found {
				return &PluginDeliverResponse{Error: ErrUnauthorized("settlement domain activation lacks quorum-certified finalized validator authority")}
			}
		}
		if prior.Active && !domain.Active {
			deactivatesDomain = true
			generation := settlementDomainDeactivationGeneration(domain.Id, params.Revision, clock.CurrentEpoch)
			records[string(KeyForSettlementDomainDeactivation(domain.Id))] = &ReplayMarker{Id: generation}
			records[string(KeyForSettlementDomainDeactivationEpoch(domain.Id))] = &ReplayMarker{Id: uint64Bytes(clock.CurrentEpoch)}
		}
	}
	if authorityMembershipChanged || activatesDomain || deactivatesDomain {
		if clock.ValidatorHandoffPrepared || clock.ValidatorHandoffTimestamp != 0 {
			return &PluginDeliverResponse{Error: ErrConflict("settlement-domain membership or traffic state cannot change during a prepared validator handoff")}
		}
	}
	if current.Revision != 0 {
		nextDomains := make(map[string]struct{}, len(params.SettlementDomains))
		for _, domain := range params.SettlementDomains {
			nextDomains[string(domain.Id)] = struct{}{}
		}
		for _, domain := range current.SettlementDomains {
			if _, retained := nextDomains[string(domain.Id)]; !retained {
				removesDomain = true
				if domain.Active {
					return &PluginDeliverResponse{Error: ErrInvalidTransaction("active settlement domains cannot be retired")}
				}
				if found, readErr := c.read(KeyForSettlementDomainRetirement(domain.Id), new(ReplayMarker)); readErr != nil {
					return &PluginDeliverResponse{Error: readErr}
				} else if !found {
					if deactivated, deactivationErr := c.read(KeyForSettlementDomainDeactivation(domain.Id), new(ReplayMarker)); deactivationErr != nil {
						return &PluginDeliverResponse{Error: deactivationErr}
					} else if deactivated {
						return &PluginDeliverResponse{Error: ErrUnauthorized("settlement-domain removal requires a finalized retirement or emergency-abandonment certificate")}
					}
					// A never-active staged domain cannot hold protocol custody. Let
					// governance discard it without fabricating a deactivation and
					// retirement ceremony, while permanently reserving its identity.
					records[string(KeyForSettlementDomainRetirement(domain.Id))] = &ReplayMarker{Id: hashFields(
						[]byte("takusen:staged-domain-discard"), domain.Id, uint64Bytes(params.Revision),
					)}
				}
			}
		}
	}
	if removesDomain && (clock.ValidatorHandoffPrepared || clock.ValidatorHandoffTimestamp != 0) {
		return &PluginDeliverResponse{Error: ErrConflict("settlement-domain retirement cannot overlap a prepared validator handoff")}
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

const maximumLifecycleIntentEpochs = 168

func settlementDomainLifecycleIntentID(domainID, generation []byte, action string, nonce, expiresAtEpoch uint64) []byte {
	return hashFields(
		[]byte("takusen:settlement-domain-lifecycle-intent"), domainID, generation, []byte(action),
		uint64Bytes(nonce), uint64Bytes(expiresAtEpoch),
	)
}

func (c *Contract) deliverGovernedSettlementDomainLifecycleIntent(value []byte) *PluginDeliverResponse {
	encoded, decodeErr := base64.StdEncoding.DecodeString(string(value))
	if decodeErr != nil {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("governed lifecycle intent is not canonical base64")}
	}
	intent := new(SettlementDomainLifecycleIntent)
	if err := Unmarshal(encoded, intent); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if len(intent.SettlementDomainId) != 32 || len(intent.DeactivationGeneration) != 32 || intent.Nonce == 0 ||
		(intent.Action != "retire" && intent.Action != "cancel" && intent.Action != "abandon") {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid settlement-domain lifecycle intent")}
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	domain, domainErr := settlementDomain(params, intent.SettlementDomainId, false)
	if domainErr != nil || domain.Active {
		return &PluginDeliverResponse{Error: ErrUnauthorized("lifecycle intent requires a governed inactive settlement domain")}
	}
	clock, clockErr := c.currentEpochClock(params)
	if clockErr != nil {
		return &PluginDeliverResponse{Error: clockErr}
	}
	if clock.ValidatorHandoffPrepared || clock.ValidatorHandoffTimestamp != 0 {
		return &PluginDeliverResponse{Error: ErrConflict("lifecycle intent cannot begin during a prepared validator handoff")}
	}
	if intent.ExpiresAtEpoch <= clock.CurrentEpoch || intent.ExpiresAtEpoch-clock.CurrentEpoch > maximumLifecycleIntentEpochs {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("lifecycle intent expiry must be within 168 epochs")}
	}
	deactivation := new(ReplayMarker)
	if found, readErr := c.read(KeyForSettlementDomainDeactivation(intent.SettlementDomainId), deactivation); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || !bytes.Equal(deactivation.Id, intent.DeactivationGeneration) {
		return &PluginDeliverResponse{Error: ErrConflict("lifecycle intent does not match the current deactivation generation")}
	}
	prior := new(SettlementDomainLifecycleIntent)
	if found, readErr := c.read(KeyForSettlementDomainLifecycleIntent(intent.SettlementDomainId), prior); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found {
		if prior.ExpiresAtEpoch >= clock.CurrentEpoch {
			return &PluginDeliverResponse{Error: ErrConflict("an unexpired settlement-domain lifecycle intent already exists")}
		}
		if intent.Nonce != prior.Nonce+1 {
			return &PluginDeliverResponse{Error: ErrConflict("lifecycle intent nonce must increase by one")}
		}
	} else if intent.Nonce != 1 {
		return &PluginDeliverResponse{Error: ErrConflict("first lifecycle intent nonce must be one")}
	}
	expectedID := settlementDomainLifecycleIntentID(
		intent.SettlementDomainId, intent.DeactivationGeneration, intent.Action, intent.Nonce, intent.ExpiresAtEpoch,
	)
	if !bytes.Equal(intent.Id, expectedID) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("lifecycle intent identifier does not match its governed fields")}
	}
	if writeErr := c.write(map[string]proto.Message{string(KeyForSettlementDomainLifecycleIntent(intent.SettlementDomainId)): intent}); writeErr != nil {
		return &PluginDeliverResponse{Error: writeErr}
	}
	return &PluginDeliverResponse{}
}

func settlementDomainDeactivationEpoch(marker *ReplayMarker) (uint64, bool) {
	if marker == nil || len(marker.Id) != 8 {
		return 0, false
	}
	return binary.BigEndian.Uint64(marker.Id), true
}

func settlementDomainDeactivationGeneration(domainID []byte, revision, epoch uint64) []byte {
	return hashFields(
		[]byte("takusen:settlement-domain-deactivation"), domainID, uint64Bytes(revision), uint64Bytes(epoch),
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
