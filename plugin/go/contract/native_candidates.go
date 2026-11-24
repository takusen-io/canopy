package contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"
)

const (
	// Leave capacity for validator-local finalized-EVM observations even when
	// Native authorizations are continuously backlogged.
	maxNativeAuxiliaryCandidates = 64
)

var nativeCandidateCategoryLimits = map[string]int{
	"priority": 32, "settlement": 64, "reward": 3, "bridge": 3,
	"abandonment": 1, "lifecycle": 2, "governance": 2,
}

type certifiedEVMObservation struct {
	Kind               string `json:"kind"`
	SettlementDomainID []byte `json:"settlementDomainId"`
	BlockNumber        uint64 `json:"blockNumber"`
	BlockHash          []byte `json:"blockHash"`
	Message            []byte `json:"message"`
}

func evmObservationDigest(observation *certifiedEVMObservation, subject []byte) []byte {
	return hashFields(
		[]byte("takusen:evm-observation:v1"), []byte(observation.Kind), observation.SettlementDomainID,
		uint64Bytes(observation.BlockNumber), observation.BlockHash, subject,
	)
}

func (c *Contract) nativeAuxiliaryCandidates(height uint64, params *ProtocolParams, priority ...*AuxiliaryCandidate) ([]*AuxiliaryCandidate, *PluginError) {
	result := make([]*AuxiliaryCandidate, 0, maxNativeAuxiliaryCandidates)
	categoryCounts := make(map[string]int, len(nativeCandidateCategoryLimits))
	appendCandidate := func(category string, candidate *AuxiliaryCandidate) {
		if candidate == nil || len(result) == maxNativeAuxiliaryCandidates {
			return
		}
		if categoryCounts[category] >= nativeCandidateCategoryLimits[category] {
			return
		}
		for _, existing := range result {
			if existing.Kind == candidate.Kind && bytes.Equal(existing.Key, candidate.Key) {
				return
			}
		}
		if found, _ := c.read(KeyForConsensusCertificate(candidate.Kind, candidate.Key, candidate.Digest), new(ConsensusCertificate)); found {
			return
		}
		result = append(result, candidate)
		categoryCounts[category]++
	}
	for _, candidate := range priority {
		appendCandidate("priority", candidate)
	}
	clock, clockErr := c.currentEpochClock(params)
	if clockErr != nil {
		return nil, clockErr
	}
	settlements, settlementErr := c.settlementAuxiliaryCandidates(clock, maxNativeAuxiliaryCandidates-len(result))
	if settlementErr != nil {
		return nil, settlementErr
	}
	for _, candidate := range settlements {
		appendCandidate("settlement", candidate)
	}

	epochs, err := c.rangeReadPage(PendingEpochAuthorizationPrefix(), nil, maxNativeAuxiliaryCandidates)
	if err != nil {
		return nil, err
	}
	for _, entry := range epochs {
		marker := new(ReplayMarker)
		if Unmarshal(entry.Value, marker) != nil || len(marker.Id) != 8 {
			continue
		}
		authorization := new(EpochAuthorization)
		if found, readErr := c.read(KeyForEpochAuthorization(bytesToUint64(marker.Id)), authorization); readErr != nil {
			return nil, readErr
		} else if !found || authorization.Status != "authorized" || len(authorization.CanonicalChainDigest) != 32 {
			continue
		}
		certificateAuthorization := proto.Clone(authorization).(*EpochAuthorization)
		if certificateAuthorization.ValidatorSetId != clock.ValidatorSetId {
			var recipients [][]byte
			var amounts []uint64
			for _, allocation := range certificateAuthorization.Allocations {
				if allocation.Amount != 0 {
					recipients = append(recipients, append([]byte(nil), allocation.CanonicalChainRecipient...))
					amounts = append(amounts, allocation.Amount)
				}
			}
			if certificateAuthorization.TreasuryAmount != 0 {
				recipients = append(recipients, append([]byte(nil), certificateAuthorization.TreasuryAddress...))
				amounts = append(amounts, certificateAuthorization.TreasuryAmount)
			}
			certificateAuthorization.ValidatorSetId = clock.ValidatorSetId
			certificateAuthorization.CanonicalChainDigest = epochAuthorizationDigest(params, clock.ValidatorSetId, certificateAuthorization.Epoch, recipients, amounts)
		}
		payload, marshalErr := json.Marshal(certificateAuthorization)
		if marshalErr != nil {
			return nil, ErrState("encode epoch reward certificate payload")
		}
		appendCandidate("reward", &AuxiliaryCandidate{Kind: "epoch-rewards", Key: append([]byte(nil), marker.Id...), Digest: append([]byte(nil), certificateAuthorization.CanonicalChainDigest...), Payload: payload})
	}

	burns, err := c.rangeReadPage(PendingBridgeBurnPrefix(), nil, maxNativeAuxiliaryCandidates)
	if err != nil {
		return nil, err
	}
	batch := &BridgeReleaseBatch{ValidatorSetId: clock.ValidatorSetId}
	for _, entry := range burns {
		marker := new(ReplayMarker)
		if Unmarshal(entry.Value, marker) != nil || len(marker.Id) != 32 {
			continue
		}
		burn := new(BridgeBurn)
		if found, readErr := c.read(KeyForBridgeBurn(marker.Id), burn); readErr != nil {
			return nil, readErr
		} else if !found || burn.Status != "pending_release" {
			continue
		}
		certificateBurn := proto.Clone(burn).(*BridgeBurn)
		batch.Releases = append(batch.Releases, certificateBurn)
	}
	if len(batch.Releases) != 0 {
		keyFields := make([][]byte, 1, len(batch.Releases)+1)
		keyFields[0] = []byte("takusen:bridge-release-batch")
		for _, release := range batch.Releases {
			keyFields = append(keyFields, release.BurnId)
		}
		batch.BatchId = hashFields(keyFields...)
		batch.CanonicalChainDigest = bridgeReleaseBatchDigest(params, clock.ValidatorSetId, batch.Releases)
		payload, marshalErr := json.Marshal(batch)
		if marshalErr != nil {
			return nil, ErrState("encode bridge release batch payload")
		}
		appendCandidate("bridge", &AuxiliaryCandidate{Kind: "bridge-release-batch", Key: append([]byte(nil), batch.BatchId...), Digest: append([]byte(nil), batch.CanonicalChainDigest...), Payload: payload})
	}

	// Emergency abandonment is an explicit governed resolution plus the delay
	// snapshotted when this domain was deactivated. Consensus participation
	// certifies only that deterministic state; it is not itself a governance vote.
	for _, domain := range params.SettlementDomains {
		if len(result) == maxNativeAuxiliaryCandidates || domain == nil || domain.State != domainStateDeactivated || len(domain.Id) != 32 {
			continue
		}
		intent := new(SettlementDomainAction)
		if found, readErr := c.read(KeyForSettlementDomainAction(domain.Id), intent); readErr != nil {
			return nil, readErr
		} else if !found || intent.Action != "resolve" || intent.Resolution != "abandon" || intent.ExpiresAtTimestamp < clock.ConsensusTimeSeconds {
			continue
		}
		deactivated := new(SettlementDomainDeactivationSnapshot)
		if found, readErr := c.read(KeyForSettlementDomainDeactivation(domain.Id), deactivated); readErr != nil {
			return nil, readErr
		} else if !found {
			continue
		}
		if len(deactivated.Generation) != 32 || deactivated.Timestamp == 0 ||
			deactivated.AbandonmentDelaySeconds < minimumDomainAbandonmentDelaySeconds ||
			!bytes.Equal(deactivated.SettlementDomainId, domain.Id) ||
			!bytes.Equal(deactivated.Generation, intent.DeactivationGeneration) || clock.ConsensusTimeSeconds < deactivated.Timestamp ||
			clock.ConsensusTimeSeconds-deactivated.Timestamp < deactivated.AbandonmentDelaySeconds {
			continue
		}
		message := &EVMControlEvidence{
			ProofKind: "settlement-domain-abandonment", ValidatorSetId: clock.ValidatorSetId,
			SettlementDomainId: append([]byte(nil), domain.Id...), HandoffGeneration: append([]byte(nil), intent.DeactivationGeneration...),
			LifecycleIntentId: append([]byte(nil), intent.Id...), Epoch: deactivated.Timestamp, ControlBlockNumber: clock.ConsensusTimeSeconds,
		}
		message.Digest = hashFields(
			[]byte("takusen:settlement-domain-abandonment"), domain.Id, uint64Bytes(clock.ValidatorSetId),
			intent.DeactivationGeneration, intent.Id, uint64Bytes(deactivated.Timestamp),
			uint64Bytes(deactivated.AbandonmentDelaySeconds), uint64Bytes(clock.ConsensusTimeSeconds),
		)
		message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
		payload, marshalErr := Marshal(message)
		if marshalErr != nil {
			return nil, marshalErr
		}
		appendCandidate("abandonment", &AuxiliaryCandidate{Kind: message.ProofKind, Key: append([]byte(nil), domain.Id...), Digest: append([]byte(nil), message.Digest...), Payload: payload})
	}

	for _, domain := range params.SettlementDomains {
		if len(result) == maxNativeAuxiliaryCandidates || domain == nil || domain.State != domainStateDeactivated || len(domain.Id) != 32 {
			continue
		}
		intent := new(SettlementDomainAction)
		if found, readErr := c.read(KeyForSettlementDomainAction(domain.Id), intent); readErr != nil {
			return nil, readErr
		} else if !found || intent.ExpiresAtTimestamp < clock.ConsensusTimeSeconds ||
			(intent.Action != "resolve" || intent.Resolution != "clean") && intent.Action != "reactivate" {
			continue
		}
		readinessKind, authorizationKind := "settlement-domain-retirement-readiness", "settlement-domain-retirement-action"
		if intent.Action == "reactivate" {
			readinessKind, authorizationKind = "settlement-domain-retirement-cancellation-readiness", "settlement-domain-retirement-cancellation"
		}
		readiness := new(QuorumProof)
		if found, readErr := c.read(KeyForNativeAuthorizationIntent(readinessKind, domain.Id), readiness); readErr != nil {
			return nil, readErr
		} else if !found || readiness.ValidatorSetId != clock.ValidatorSetId || readiness.RotationNonce == 0 ||
			readiness.HandoffTimestamp <= clock.ConsensusTimeSeconds || len(readiness.Digest) != 32 ||
			!bytes.Equal(readiness.HandoffGeneration, intent.DeactivationGeneration) || !bytes.Equal(readiness.LifecycleIntentId, intent.Id) {
			continue
		}
		message := &EVMControlEvidence{
			ProofKind: authorizationKind, ValidatorSetId: clock.ValidatorSetId, Digest: append([]byte(nil), readiness.Digest...),
			SettlementDomainId: append([]byte(nil), domain.Id...),
			RotationNonce:      readiness.RotationNonce, HandoffGeneration: append([]byte(nil), intent.DeactivationGeneration...),
			HandoffTimestamp: readiness.HandoffTimestamp, ControlBlockNumber: readiness.ControlBlockNumber,
			ControlBlockHash: append([]byte(nil), readiness.ControlBlockHash...), LifecycleIntentId: append([]byte(nil), intent.Id...),
		}
		message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
		payload, marshalErr := Marshal(message)
		if marshalErr != nil {
			return nil, marshalErr
		}
		key := hashFields(domain.Id, uint64Bytes(message.RotationNonce), message.HandoffGeneration, message.LifecycleIntentId)
		appendCandidate("lifecycle", &AuxiliaryCandidate{Kind: authorizationKind, Key: key, Digest: append([]byte(nil), message.Digest...), Payload: payload})
	}

	// A human-approved Native intent is the only policy decision for an EVM
	// administrative call. Consensus vote extensions create the exact proof the
	// EVM executor consumes; validators never submit a second vote transaction.
	for _, domain := range params.SettlementDomains {
		if len(result) == maxNativeAuxiliaryCandidates || domain == nil || domain.State == domainStateResolved {
			continue
		}
		intent := new(EVMGovernanceActionIntent)
		if found, readErr := c.read(KeyForEVMGovernanceActionIntent(domain.Id), intent); readErr != nil {
			return nil, readErr
		} else if !found || intent.ValidatorSetId != clock.ValidatorSetId || intent.ExpiresAtTimestamp < clock.ConsensusTimeSeconds ||
			!bytes.Equal(intent.SettlementDomainId, domain.Id) || !bytes.Equal(intent.Digest, evmGovernanceActionDigest(domain, intent)) ||
			!bytes.Equal(intent.Id, evmGovernanceActionIntentID(intent)) {
			continue
		}
		proofID := quorumProofID("governance-action", intent.ValidatorSetId, intent.Digest)
		if found, proofErr := c.read(KeyForQuorumProof(proofID), new(QuorumProof)); proofErr != nil {
			return nil, proofErr
		} else if found {
			continue
		}
		payload, marshalErr := Marshal(intent)
		if marshalErr != nil {
			return nil, marshalErr
		}
		appendCandidate("governance", &AuxiliaryCandidate{Kind: "governance-action", Key: append([]byte(nil), intent.Id...), Digest: append([]byte(nil), intent.Digest...), Payload: payload})
	}

	return result, nil
}

// advanceSettlementCandidateCursor keeps bounded settlement discovery moving
// through the complete uncertified index. Without a durable cursor, an old
// first page can permanently hide later ready cohorts even though consensus
// still has certificate capacity.
func (c *Contract) advanceSettlementCandidateCursor(records map[string]proto.Message) *PluginError {
	next := new(ReplayMarker)
	if found, err := c.read(KeyForSettlementCandidateCursorNext(), next); err != nil {
		return err
	} else if !found {
		next.Id = nil
	}
	current := &ReplayMarker{Id: append([]byte(nil), next.Id...)}
	page, err := c.rangeReadPage(UncertifiedSettlementIndexPrefix(), current.Id, settlementCandidatePageSize)
	if err != nil {
		return err
	}
	following := &ReplayMarker{}
	if uint64(len(page)) == settlementCandidatePageSize {
		following.Id = append([]byte(nil), page[len(page)-1].Key...)
	}
	records[string(KeyForSettlementCandidateCursorCurrent())] = current
	records[string(KeyForSettlementCandidateCursorNext())] = following
	return nil
}

func bytesToUint64(value []byte) uint64 {
	if len(value) != 8 {
		return 0
	}
	return uint64(value[0])<<56 | uint64(value[1])<<48 | uint64(value[2])<<40 | uint64(value[3])<<32 |
		uint64(value[4])<<24 | uint64(value[5])<<16 | uint64(value[6])<<8 | uint64(value[7])
}

func auxiliaryProofRecord(height uint64, candidate *AuxiliaryCandidate, certificate *ConsensusCertificate) *QuorumProof {
	return &QuorumProof{
		ProofKind: candidate.Kind, ProofId: quorumProofID(candidate.Kind, certificate.ValidatorSetId, candidate.Digest),
		Digest: append([]byte(nil), candidate.Digest...), ValidatorSetId: certificate.ValidatorSetId,
		SignerBitmap: append([]byte(nil), certificate.SignerBitmap...), AggregateSignatureEip2537: append([]byte(nil), certificate.AggregateSignatureEip2537...),
		SignedWeight: certificate.SignedWeight, TotalWeight: certificate.TotalWeight, CompletedHeight: height,
	}
}

func (c *Contract) applyNativeAuxiliaryCertificate(height uint64, candidate *AuxiliaryCandidate, certificate *ConsensusCertificate, records map[string]proto.Message, deletes *[][]byte) bool {
	if strings.HasPrefix(candidate.Kind, "evm-observation/") {
		return c.applyEVMObservationCertificate(height, candidate, certificate, records)
	}
	switch candidate.Kind {
	case "enclave-revocation":
		message := new(EnclaveRevocation)
		if Unmarshal(candidate.Payload, message) != nil || checkEnclaveRevocation(message) != nil ||
			!bytes.Equal(candidate.Key, enclaveRevocationKey(message)) ||
			!bytes.Equal(candidate.Digest, enclaveRevocationDigest(message)) {
			return false
		}
		return c.applyEnclaveRevocation(message, records, deletes)
	case "epoch-rewards":
		authorization := new(EpochAuthorization)
		if json.Unmarshal(candidate.Payload, authorization) != nil || authorization.Status != "authorized" ||
			len(candidate.Key) != 8 || authorization.Epoch != bytesToUint64(candidate.Key) ||
			!bytes.Equal(candidate.Digest, authorization.CanonicalChainDigest) {
			return false
		}
	case "bridge-release-batch":
		batch := new(BridgeReleaseBatch)
		if json.Unmarshal(candidate.Payload, batch) != nil || len(batch.Releases) == 0 || len(batch.Releases) > 64 ||
			!bytes.Equal(candidate.Key, batch.BatchId) || !bytes.Equal(candidate.Digest, batch.CanonicalChainDigest) || batch.ValidatorSetId != certificate.ValidatorSetId {
			return false
		}
		params, err := c.currentProtocolParams()
		if err != nil {
			return false
		}
		keyFields := make([][]byte, 1, len(batch.Releases)+1)
		keyFields[0] = []byte("takusen:bridge-release-batch")
		seen := make(map[string]struct{}, len(batch.Releases))
		for index, release := range batch.Releases {
			if release == nil || len(release.BurnId) != 32 || release.Status != "pending_release" {
				return false
			}
			if _, duplicate := seen[string(release.BurnId)]; duplicate {
				return false
			}
			seen[string(release.BurnId)] = struct{}{}
			committed := new(BridgeBurn)
			if found, readErr := c.read(KeyForBridgeBurn(release.BurnId), committed); readErr != nil || !found ||
				committed.Status != "pending_release" || !proto.Equal(committed, release) {
				return false
			}
			keyFields[index+1] = release.BurnId
		}
		if !bytes.Equal(batch.BatchId, hashFields(keyFields...)) ||
			!bytes.Equal(batch.CanonicalChainDigest, bridgeReleaseBatchDigest(params, batch.ValidatorSetId, batch.Releases)) {
			return false
		}
	case "settlement":
		batch := new(certifiedSettlementBatch)
		if json.Unmarshal(candidate.Payload, batch) != nil || batch.ValidatorSetID != certificate.ValidatorSetId ||
			len(batch.Requests) == 0 || len(batch.Requests) > maxSettlementRequestsPerCertificate || batch.Digest != "0x"+hex.EncodeToString(candidate.Digest) {
			return false
		}
	case "settlement-domain-abandonment":
		message := new(EVMControlEvidence)
		if Unmarshal(candidate.Payload, message) != nil || message.ProofKind != candidate.Kind ||
			!bytes.Equal(candidate.Key, message.SettlementDomainId) || !bytes.Equal(candidate.Digest, message.Digest) ||
			message.ValidatorSetId != certificate.ValidatorSetId {
			return false
		}
		if !c.persistCertifiedNativeAbandonment(height, message, certificate, records) {
			return false
		}
		return true
	case "settlement-domain-retirement-action", "settlement-domain-retirement-cancellation":
		message := new(EVMControlEvidence)
		if Unmarshal(candidate.Payload, message) != nil || message.ProofKind != candidate.Kind ||
			message.ValidatorSetId != certificate.ValidatorSetId || !bytes.Equal(candidate.Digest, message.Digest) ||
			!bytes.Equal(candidate.Key, hashFields(message.SettlementDomainId, uint64Bytes(message.RotationNonce), message.HandoffGeneration, message.LifecycleIntentId)) {
			return false
		}
		intent := new(SettlementDomainAction)
		found, readErr := c.read(KeyForSettlementDomainAction(message.SettlementDomainId), intent)
		readinessKind, expectedAction, expectedResolution := "settlement-domain-retirement-readiness", "resolve", "clean"
		if candidate.Kind == "settlement-domain-retirement-cancellation" {
			readinessKind, expectedAction, expectedResolution = "settlement-domain-retirement-cancellation-readiness", "reactivate", ""
		}
		readiness := new(QuorumProof)
		foundReadiness, readinessErr := c.read(KeyForNativeAuthorizationIntent(readinessKind, message.SettlementDomainId), readiness)
		params, paramsErr := c.currentProtocolParams()
		if paramsErr != nil {
			return false
		}
		clock, clockErr := c.currentEpochClock(params)
		if readErr != nil || !found || readinessErr != nil || !foundReadiness || clockErr != nil ||
			intent.Action != expectedAction || intent.Resolution != expectedResolution || intent.ExpiresAtTimestamp < clock.ConsensusTimeSeconds || message.HandoffTimestamp <= clock.ConsensusTimeSeconds ||
			readiness.RotationNonce != message.RotationNonce || !bytes.Equal(readiness.Digest, message.Digest) ||
			!bytes.Equal(intent.Id, message.LifecycleIntentId) || !bytes.Equal(intent.DeactivationGeneration, message.HandoffGeneration) {
			return false
		}
		proof := auxiliaryProofRecord(height, candidate, certificate)
		proof.ProofKind, proof.ProofId = message.ProofKind, append([]byte(nil), message.ProofId...)
		proof.RotationNonce = message.RotationNonce
		proof.SettlementDomainId = append([]byte(nil), message.SettlementDomainId...)
		proof.HandoffGeneration = append([]byte(nil), message.HandoffGeneration...)
		proof.HandoffTimestamp = message.HandoffTimestamp
		proof.ControlBlockNumber = message.ControlBlockNumber
		proof.ControlBlockHash = append([]byte(nil), message.ControlBlockHash...)
		proof.LifecycleIntentId = append([]byte(nil), message.LifecycleIntentId...)
		records[string(KeyForQuorumProof(proof.ProofId))] = proof
		return true
	case "governance-action":
		intent := new(EVMGovernanceActionIntent)
		if Unmarshal(candidate.Payload, intent) != nil || intent.ValidatorSetId != certificate.ValidatorSetId ||
			!bytes.Equal(candidate.Key, intent.Id) || !bytes.Equal(candidate.Digest, intent.Digest) ||
			!bytes.Equal(intent.Id, evmGovernanceActionIntentID(intent)) {
			return false
		}
		params, paramsErr := c.currentProtocolParams()
		if paramsErr != nil {
			return false
		}
		domain, domainErr := settlementDomain(params, intent.SettlementDomainId, false)
		clock, clockErr := c.currentEpochClock(params)
		if domainErr != nil || clockErr != nil || domain.State == domainStateResolved ||
			intent.ExpiresAtTimestamp < clock.ConsensusTimeSeconds || !bytes.Equal(intent.Digest, evmGovernanceActionDigest(domain, intent)) {
			return false
		}
	default:
		return true
	}
	proof := auxiliaryProofRecord(height, candidate, certificate)
	records[string(KeyForQuorumProof(proof.ProofId))] = proof
	return true
}

func (c *Contract) persistCertifiedNativeAbandonment(height uint64, message *EVMControlEvidence, certificate *ConsensusCertificate, records map[string]proto.Message) bool {
	params, err := c.currentProtocolParams()
	if err != nil {
		return false
	}
	domain, domainErr := settlementDomain(params, message.SettlementDomainId, false)
	clock, clockErr := c.currentEpochClock(params)
	intent := new(SettlementDomainAction)
	foundIntent, intentErr := c.read(KeyForSettlementDomainAction(message.SettlementDomainId), intent)
	deactivated := new(SettlementDomainDeactivationSnapshot)
	foundDeactivation, deactivationErr := c.read(KeyForSettlementDomainDeactivation(message.SettlementDomainId), deactivated)
	if domainErr != nil || domain.State != domainStateDeactivated || clockErr != nil || intentErr != nil || !foundIntent || deactivationErr != nil || !foundDeactivation ||
		intent.Action != "resolve" || intent.Resolution != "abandon" || intent.ExpiresAtTimestamp < clock.ConsensusTimeSeconds ||
		len(deactivated.Generation) != 32 || deactivated.Timestamp == 0 ||
		deactivated.AbandonmentDelaySeconds < minimumDomainAbandonmentDelaySeconds || message.Epoch != deactivated.Timestamp ||
		clock.ConsensusTimeSeconds != message.ControlBlockNumber || clock.ConsensusTimeSeconds < deactivated.Timestamp ||
		clock.ConsensusTimeSeconds-deactivated.Timestamp < deactivated.AbandonmentDelaySeconds ||
		!bytes.Equal(deactivated.SettlementDomainId, message.SettlementDomainId) ||
		!bytes.Equal(deactivated.Generation, message.HandoffGeneration) ||
		!bytes.Equal(intent.Id, message.LifecycleIntentId) || !bytes.Equal(intent.DeactivationGeneration, message.HandoffGeneration) {
		return false
	}
	expected := hashFields(
		[]byte("takusen:settlement-domain-abandonment"), message.SettlementDomainId, uint64Bytes(clock.ValidatorSetId),
		message.HandoffGeneration, message.LifecycleIntentId, uint64Bytes(deactivated.Timestamp),
		uint64Bytes(deactivated.AbandonmentDelaySeconds), uint64Bytes(clock.ConsensusTimeSeconds),
	)
	if !bytes.Equal(expected, candidateDigest(message)) {
		return false
	}
	proofID := quorumProofID(message.ProofKind, certificate.ValidatorSetId, certificate.Digest)
	records[string(KeyForQuorumProof(proofID))] = &QuorumProof{
		ProofKind: message.ProofKind, ProofId: proofID, Digest: append([]byte(nil), certificate.Digest...), ValidatorSetId: certificate.ValidatorSetId,
		SignerBitmap: append([]byte(nil), certificate.SignerBitmap...), AggregateSignatureEip2537: append([]byte(nil), certificate.AggregateSignatureEip2537...),
		SignedWeight: certificate.SignedWeight, TotalWeight: certificate.TotalWeight, CompletedHeight: height,
		SettlementDomainId: append([]byte(nil), message.SettlementDomainId...), HandoffGeneration: append([]byte(nil), message.HandoffGeneration...),
		LifecycleIntentId: append([]byte(nil), message.LifecycleIntentId...), ControlBlockNumber: message.ControlBlockNumber,
	}
	if !c.stageResolvedDomain(params, message.SettlementDomainId, message.HandoffGeneration, "ABANDONED", message.LifecycleIntentId, proofID, clock.ConsensusTimeSeconds, records) {
		return false
	}
	if clock.ValidatorHandoffPrepared && handoffIncludesDomain(clock, message.SettlementDomainId) {
		if c.markValidatorHandoffResolved(clock, message.SettlementDomainId, proofID, records) != nil {
			return false
		}
	}
	return true
}

func (c *Contract) stageResolvedDomain(params *ProtocolParams, domainID, generation []byte, outcome string, actionID, proofID []byte, timestamp uint64, records map[string]proto.Message) bool {
	if params == nil || len(domainID) != 32 || len(generation) != 32 || (outcome != "RETIRED" && outcome != "ABANDONED") ||
		len(actionID) != 32 || len(proofID) != 32 || timestamp == 0 {
		return false
	}
	next := proto.Clone(params).(*ProtocolParams)
	found := false
	for _, domain := range next.SettlementDomains {
		if domain != nil && bytes.Equal(domain.Id, domainID) {
			if domain.State != domainStateDeactivated {
				return false
			}
			domain.State = domainStateResolved
			found = true
			break
		}
	}
	if !found {
		return false
	}
	records[string(KeyForProtocolParams())] = next
	records[string(KeyForSettlementDomainResolution(domainID))] = &SettlementDomainResolution{
		SettlementDomainId: append([]byte(nil), domainID...), DeactivationGeneration: append([]byte(nil), generation...),
		Outcome: outcome, GovernanceActionId: append([]byte(nil), actionID...), ProofId: append([]byte(nil), proofID...), CompletedTimestamp: timestamp,
	}
	return true
}

func candidateDigest(message *EVMControlEvidence) []byte { return message.Digest }

func (c *Contract) applyEVMObservationCertificate(height uint64, candidate *AuxiliaryCandidate, certificate *ConsensusCertificate, records map[string]proto.Message) bool {
	kind := strings.TrimPrefix(candidate.Kind, "evm-observation/")
	observation := new(certifiedEVMObservation)
	if kind == candidate.Kind || json.Unmarshal(candidate.Payload, observation) != nil || observation.Kind != kind ||
		len(observation.SettlementDomainID) != 32 || observation.BlockNumber == 0 || len(observation.BlockHash) != 32 || len(observation.Message) == 0 {
		return false
	}
	apply := func(subject, claim []byte, deliver func() *PluginDeliverResponse) bool {
		if !bytes.Equal(candidate.Key, hashFields([]byte(kind), observation.SettlementDomainID, claim)) ||
			!bytes.Equal(candidate.Digest, evmObservationDigest(observation, subject)) {
			return false
		}
		response := deliver()
		return response != nil && response.Error == nil
	}
	switch kind {
	case "authorization":
		message := new(Authorization)
		if Unmarshal(observation.Message, message) != nil || message.DirectEoa ||
			!bytes.Equal(message.SettlementDomainId, observation.SettlementDomainID) ||
			message.AuthorizationChainBlockNumber != observation.BlockNumber || !bytes.Equal(message.AuthorizationChainBlockHash, observation.BlockHash) {
			return false
		}
		return apply(authorizationSubject(message), []byte(message.RequestId), func() *PluginDeliverResponse {
			return c.applyAuthorizationItem(height, message, true)
		})
	case "deposit":
		message := new(MessageObserveDeposit)
		if Unmarshal(observation.Message, message) != nil || len(message.ObserverAddress) != 0 ||
			!bytes.Equal(message.SettlementDomainId, observation.SettlementDomainID) {
			return false
		}
		return apply(depositSubject(message), message.ChainTxHash, func() *PluginDeliverResponse { return c.deliverObserveDepositCertified(height, message, true) })
	case "bridge-lock":
		message := new(MessageObserveBridgeLock)
		if Unmarshal(observation.Message, message) != nil || len(message.ObserverAddress) != 0 {
			return false
		}
		claim := append(append([]byte(nil), message.CanonicalChainTxHash...), uint64Bytes(message.Nonce)...)
		return apply(bridgeLockSubject(message), claim, func() *PluginDeliverResponse { return c.deliverObserveBridgeLockCertified(height, message, true) })
	case "bridge-release":
		message := new(MessageObserveBridgeRelease)
		if Unmarshal(observation.Message, message) != nil || len(message.ObserverAddress) != 0 || message.ValidatorSetId != certificate.ValidatorSetId {
			return false
		}
		subject := hashFields([]byte("takusen:bridge-release"), message.BurnId, message.CanonicalChainTxHash, uint64Bytes(message.Nonce), message.CanonicalChainRecipient, uint64Bytes(message.Amount), uint64Bytes(message.ValidatorSetId))
		return apply(subject, message.BurnId, func() *PluginDeliverResponse { return c.deliverObserveBridgeReleaseCertified(height, message, true) })
	case "epoch-mint":
		message := new(MessageObserveEpochMint)
		if Unmarshal(observation.Message, message) != nil || len(message.ObserverAddress) != 0 || message.ValidatorSetId != certificate.ValidatorSetId {
			return false
		}
		subject := hashFields([]byte("takusen:epoch-mint"), uint64Bytes(message.Epoch), message.CanonicalChainTxHash, uint64Bytes(message.ValidatorSetId))
		return apply(subject, uint64Bytes(message.Epoch), func() *PluginDeliverResponse { return c.deliverObserveEpochMintCertified(height, message, true) })
	case "settlement-finalization":
		reference := new(MessageFinalizeSettlementBatch)
		if Unmarshal(observation.Message, reference) != nil ||
			!bytes.Equal(reference.SettlementDomainId, observation.SettlementDomainID) ||
			len(reference.SettlementTxHash) != 32 || reference.BatchNonce == 0 || len(reference.SettlementCertificateDigest) != 32 {
			return false
		}
		message, valid := c.finalizationsForSettlementReference(reference)
		if !valid {
			return false
		}
		claim := hashFields(reference.SettlementTxHash)
		return apply(settlementReferenceSubject(reference), claim, func() *PluginDeliverResponse { return c.deliverFinalizeRequestsConsensus(height, message) })
	case "validator-set-rotation-queued",
		"settlement-domain-authority", "settlement-domain-retirement-readiness", "settlement-domain-retirement-cancellation-readiness",
		"settlement-domain-retirement-cancelled", "settlement-domain-retired":
		message := new(EVMControlEvidence)
		if Unmarshal(observation.Message, message) != nil || message.ProofKind != kind ||
			!bytes.Equal(message.SettlementDomainId, observation.SettlementDomainID) ||
			(kind != "settlement-domain-retired" && kind != "settlement-domain-retirement-cancelled" && message.ValidatorSetId != certificate.ValidatorSetId) {
			return false
		}
		if (kind == "validator-set-rotation-queued" || kind == "settlement-domain-authority" || strings.HasPrefix(kind, "settlement-domain-retirement")) &&
			(message.ControlBlockNumber != observation.BlockNumber || !bytes.Equal(message.ControlBlockHash, observation.BlockHash)) {
			return false
		}
		claim := message.ProofId
		if kind == "settlement-domain-retirement-readiness" || kind == "settlement-domain-retirement-cancellation-readiness" {
			claim = hashFields(uint64Bytes(message.RotationNonce), message.HandoffGeneration, message.LifecycleIntentId)
		}
		if !apply(message.Digest, claim, func() *PluginDeliverResponse { return &PluginDeliverResponse{} }) {
			return false
		}
		return c.persistCertifiedEVMControlEvidence(height, message, certificate, records)
	default:
		return false
	}
}

// finalizationsForSettlementReference reconstructs the complete finalization
// cohort from the already-certified Native settlement payload. The compact EVM
// observation therefore never becomes an external data-availability dependency.
func (c *Contract) finalizationsForSettlementReference(reference *MessageFinalizeSettlementBatch) (*MessageFinalizeRequests, bool) {
	certificate := new(ConsensusCertificate)
	found, err := c.read(KeyForConsensusCertificate(
		"settlement", uint64Bytes(reference.BatchNonce), reference.SettlementCertificateDigest,
	), certificate)
	if err != nil || !found || certificate.Kind != "settlement" ||
		!bytes.Equal(certificate.Key, uint64Bytes(reference.BatchNonce)) ||
		!bytes.Equal(certificate.Digest, reference.SettlementCertificateDigest) {
		return nil, false
	}
	batch := new(certifiedSettlementBatch)
	if json.Unmarshal(certificate.Payload, batch) != nil || batch.BatchNonce != reference.BatchNonce ||
		batch.ValidatorSetID != certificate.ValidatorSetId || batch.Digest != "0x"+hex.EncodeToString(reference.SettlementCertificateDigest) ||
		len(batch.Requests) == 0 || len(batch.Requests) > maxSettlementRequestsPerCertificate {
		return nil, false
	}
	requests := make([]*RequestFinalization, len(batch.Requests))
	for index, settled := range batch.Requests {
		domain, decodeErr := decodeHash(settled.SettlementDomain)
		if decodeErr != nil || !bytes.Equal(domain, reference.SettlementDomainId) || settled.RequestID == "" ||
			settled.ReservedBudget == 0 || settled.RequestSpent > settled.ReservedBudget || len(settled.Executions) == 0 {
			return nil, false
		}
		ordinals := make(map[string]int, len(settled.Models))
		for ordinal, model := range settled.Models {
			ordinals[model] = ordinal
		}
		executions := append([]certifiedSettlementExecution(nil), settled.Executions...)
		sort.Slice(executions, func(left, right int) bool {
			return ordinals[executions[left].Model] < ordinals[executions[right].Model]
		})
		executionIDs := make([]string, len(executions))
		for executionIndex := range executions {
			if executions[executionIndex].ExecutionID == "" {
				return nil, false
			}
			executionIDs[executionIndex] = executions[executionIndex].ExecutionID
		}
		requests[index] = &RequestFinalization{
			SettlementDomainId: append([]byte(nil), reference.SettlementDomainId...), RequestId: settled.RequestID,
			SettlementTxHash: append([]byte(nil), reference.SettlementTxHash...), ReservedBudget: settled.ReservedBudget,
			RequestSpent: settled.RequestSpent, ExecutionIds: executionIDs, FinalizesRequest: settled.FinalizesRequest,
		}
	}
	return &MessageFinalizeRequests{Requests: requests}, true
}

func (c *Contract) persistCertifiedEVMControlEvidence(height uint64, message *EVMControlEvidence, certificate *ConsensusCertificate, records map[string]proto.Message) bool {
	var handoffClock *EpochClock
	if message.ProofKind == "validator-set-rotation-queued" {
		clock, err := c.currentEpochClockFromState()
		if err != nil || !clock.ValidatorHandoffPrepared || !handoffIncludesDomain(clock, message.SettlementDomainId) ||
			message.ValidatorSetId != clock.ValidatorSetId || message.NewValidatorSetId != clock.ValidatorSetId+1 {
			return false
		}
		if !bytes.Equal(message.HandoffGeneration, validatorHandoffGeneration(clock)) || message.HandoffTimestamp != clock.ValidatorHandoffTimestamp {
			return false
		}
		handoffClock = clock
	}
	if message.ProofKind == "settlement-domain-retirement-readiness" || message.ProofKind == "settlement-domain-retirement-cancellation-readiness" {
		params, err := c.currentProtocolParams()
		if err != nil {
			return false
		}
		clock, clockErr := c.currentEpochClock(params)
		domain, domainErr := settlementDomain(params, message.SettlementDomainId, false)
		intent := new(SettlementDomainAction)
		found, intentErr := c.read(KeyForSettlementDomainAction(message.SettlementDomainId), intent)
		expectedAction, expectedResolution := "resolve", "clean"
		if message.ProofKind == "settlement-domain-retirement-cancellation-readiness" {
			expectedAction, expectedResolution = "reactivate", ""
		}
		if clockErr != nil || domainErr != nil || domain.State != domainStateDeactivated || intentErr != nil || !found ||
			intent.Action != expectedAction || intent.Resolution != expectedResolution || intent.ExpiresAtTimestamp < clock.ConsensusTimeSeconds || message.RotationNonce == 0 ||
			message.HandoffTimestamp == 0 || message.ControlBlockNumber == 0 || len(message.ControlBlockHash) != 32 ||
			!bytes.Equal(intent.Id, message.LifecycleIntentId) || !bytes.Equal(intent.DeactivationGeneration, message.HandoffGeneration) {
			return false
		}
	}
	if message.ProofKind == "settlement-domain-retired" || message.ProofKind == "settlement-domain-retirement-cancelled" {
		params, err := c.currentProtocolParams()
		if err != nil {
			return false
		}
		domain, domainErr := settlementDomain(params, message.SettlementDomainId, false)
		intent := new(SettlementDomainAction)
		found, intentErr := c.read(KeyForSettlementDomainAction(message.SettlementDomainId), intent)
		expectedAction, expectedResolution := "resolve", "clean"
		if message.ProofKind == "settlement-domain-retirement-cancelled" {
			expectedAction, expectedResolution = "reactivate", ""
		}
		if domainErr != nil || domain.State != domainStateDeactivated || intentErr != nil || !found || intent.Action != expectedAction || intent.Resolution != expectedResolution ||
			message.RotationNonce == 0 || message.ControlBlockNumber == 0 || len(message.ControlBlockHash) != 32 ||
			!bytes.Equal(intent.Id, message.LifecycleIntentId) || !bytes.Equal(intent.DeactivationGeneration, message.HandoffGeneration) {
			return false
		}
		var expected []byte
		if message.ProofKind == "settlement-domain-retired" {
			expected = hashFields([]byte("takusen:settlement-domain-retired"), message.SettlementDomainId, uint64Bytes(message.ValidatorSetId), uint64Bytes(message.RotationNonce), message.HandoffGeneration, message.LifecycleIntentId, uint64Bytes(message.ControlBlockNumber), message.ControlBlockHash)
		} else {
			expected = hashFields([]byte("takusen:settlement-domain-retirement-cancelled"), message.SettlementDomainId, uint64Bytes(message.ValidatorSetId), uint64Bytes(message.RotationNonce), message.HandoffGeneration, message.LifecycleIntentId, uint64Bytes(message.ControlBlockNumber), message.ControlBlockHash)
		}
		if !bytes.Equal(message.Digest, expected) {
			return false
		}
	}
	proofID := quorumProofID(message.ProofKind, certificate.ValidatorSetId, certificate.Digest)
	proof := &QuorumProof{
		ProofKind: message.ProofKind, ProofId: proofID, Digest: append([]byte(nil), certificate.Digest...),
		ValidatorSetId: certificate.ValidatorSetId, SignerBitmap: append([]byte(nil), certificate.SignerBitmap...),
		AggregateSignatureEip2537: append([]byte(nil), certificate.AggregateSignatureEip2537...),
		SignedWeight:              certificate.SignedWeight, TotalWeight: certificate.TotalWeight, CompletedHeight: height,
		NewValidatorSetId: message.NewValidatorSetId, SettlementDomainId: append([]byte(nil), message.SettlementDomainId...),
		RotationNonce: message.RotationNonce, HandoffGeneration: append([]byte(nil), message.HandoffGeneration...),
		HandoffTimestamp: message.HandoffTimestamp, ControlBlockNumber: message.ControlBlockNumber,
		ControlBlockHash: append([]byte(nil), message.ControlBlockHash...), LifecycleIntentId: append([]byte(nil), message.LifecycleIntentId...),
	}
	if message.ProofKind == "validator-set-rotation-queued" &&
		!c.stageDomainRotationNonce(message.SettlementDomainId, message.RotationNonce, records) {
		return false
	}
	records[string(KeyForQuorumProof(proofID))] = proof
	switch message.ProofKind {
	case "validator-set-rotation-queued":
		records[string(KeyForQueuedRotationIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: proofID}
		if c.markValidatorHandoffResolved(handoffClock, message.SettlementDomainId, proofID, records) != nil {
			return false
		}
	case "settlement-domain-authority":
		records[string(KeyForSettlementDomainAuthority(message.SettlementDomainId, message.ValidatorSetId))] = &ReplayMarker{Id: proofID}
	case "settlement-domain-retirement-readiness", "settlement-domain-retirement-cancellation-readiness":
		proof.Digest = append([]byte(nil), message.Digest...)
		proof.RotationNonce = message.RotationNonce
		proof.HandoffGeneration = append([]byte(nil), message.HandoffGeneration...)
		proof.HandoffTimestamp = message.HandoffTimestamp
		proof.ControlBlockNumber = message.ControlBlockNumber
		proof.ControlBlockHash = append([]byte(nil), message.ControlBlockHash...)
		proof.LifecycleIntentId = append([]byte(nil), message.LifecycleIntentId...)
		records[string(KeyForNativeAuthorizationIntent(message.ProofKind, message.SettlementDomainId))] = proof
	case "settlement-domain-retirement-cancelled":
		records[string(KeyForSettlementDomainRetirementCancellation(message.SettlementDomainId, message.HandoffGeneration))] = &ReplayMarker{Id: proofID}
		params, paramsErr := c.currentProtocolParams()
		clock, clockErr := c.currentEpochClock(params)
		if paramsErr != nil || clockErr != nil || !c.stageReactivatedDomain(params, message.SettlementDomainId, clock.ValidatorSetId, records) {
			return false
		}
	case "settlement-domain-retired":
		params, paramsErr := c.currentProtocolParams()
		clock, clockErr := c.currentEpochClock(params)
		if paramsErr != nil || clockErr != nil ||
			!c.stageResolvedDomain(params, message.SettlementDomainId, message.HandoffGeneration, "RETIRED", message.LifecycleIntentId, proofID, clock.ConsensusTimeSeconds, records) {
			return false
		}
	}
	return true
}

func (c *Contract) stageReactivatedDomain(params *ProtocolParams, domainID []byte, validatorSetID uint64, records map[string]proto.Message) bool {
	if params == nil || len(domainID) != 32 || validatorSetID == 0 {
		return false
	}
	if found, err := c.read(KeyForSettlementDomainAuthority(domainID, validatorSetID), new(ReplayMarker)); err != nil || !found {
		return false
	}
	next := proto.Clone(params).(*ProtocolParams)
	for _, domain := range next.SettlementDomains {
		if domain != nil && bytes.Equal(domain.Id, domainID) {
			if domain.State != domainStateDeactivated {
				return false
			}
			domain.State = domainStateActive
			records[string(KeyForProtocolParams())] = next
			return true
		}
	}
	return false
}

func (c *Contract) stageDomainRotationNonce(domainID []byte, nonce uint64, records map[string]proto.Message) bool {
	if len(domainID) != 32 || nonce == 0 {
		return false
	}
	key := KeyForDomainRotationState(domainID)
	state := new(SettlementDomainRotationState)
	found := false
	if staged, ok := records[string(key)].(*SettlementDomainRotationState); ok {
		state = proto.Clone(staged).(*SettlementDomainRotationState)
		found = true
	} else {
		var err *PluginError
		found, err = c.read(key, state)
		if err != nil {
			return false
		}
	}
	if found {
		if !bytes.Equal(state.SettlementDomainId, domainID) || nonce < state.RotationNonce ||
			(state.RotationNonce == ^uint64(0) || nonce > state.RotationNonce+1) {
			return false
		}
	} else if nonce != 1 {
		return false
	}
	state.SettlementDomainId = append([]byte(nil), domainID...)
	if nonce > state.RotationNonce {
		state.RotationNonce = nonce
	}
	records[string(key)] = state
	return true
}
