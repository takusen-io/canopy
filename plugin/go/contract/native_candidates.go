package contract

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"google.golang.org/protobuf/proto"
)

const maxNativeAuxiliaryCandidates = 32

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
	appendCandidate := func(candidate *AuxiliaryCandidate) {
		if candidate == nil || len(result) == maxNativeAuxiliaryCandidates {
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
	}
	for _, candidate := range priority {
		appendCandidate(candidate)
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
		appendCandidate(candidate)
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
				if !allocation.Compounded && allocation.Amount != 0 {
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
		appendCandidate(&AuxiliaryCandidate{Kind: "epoch-rewards", Key: append([]byte(nil), marker.Id...), Digest: append([]byte(nil), certificateAuthorization.CanonicalChainDigest...), Payload: payload})
	}

	burns, err := c.rangeReadPage(PendingBridgeBurnPrefix(), nil, maxNativeAuxiliaryCandidates)
	if err != nil {
		return nil, err
	}
	for _, entry := range burns {
		marker := new(ReplayMarker)
		if Unmarshal(entry.Value, marker) != nil || len(marker.Id) != 32 {
			continue
		}
		burn := new(BridgeBurn)
		if found, readErr := c.read(KeyForBridgeBurn(marker.Id), burn); readErr != nil {
			return nil, readErr
		} else if !found || burn.Status != "pending_release" || len(burn.CanonicalChainDigest) != 32 {
			continue
		}
		certificateBurn := proto.Clone(burn).(*BridgeBurn)
		if certificateBurn.ValidatorSetId != clock.ValidatorSetId {
			certificateBurn.ValidatorSetId = clock.ValidatorSetId
			certificateBurn.CanonicalChainDigest = bridgeReleaseDigest(params, clock.ValidatorSetId, certificateBurn.Nonce, certificateBurn.CanonicalChainRecipient, certificateBurn.Amount, certificateBurn.BurnId)
		}
		payload, marshalErr := json.Marshal(certificateBurn)
		if marshalErr != nil {
			return nil, ErrState("encode bridge release certificate payload")
		}
		appendCandidate(&AuxiliaryCandidate{Kind: "bridge-release", Key: append([]byte(nil), marker.Id...), Digest: append([]byte(nil), certificateBurn.CanonicalChainDigest...), Payload: payload})
	}

	// Emergency abandonment is an explicit governed intent plus a fixed native
	// delay. Consensus participation certifies only that deterministic state;
	// it is not itself a governance vote.
	for _, domain := range params.SettlementDomains {
		if len(result) == maxNativeAuxiliaryCandidates || domain == nil || domain.Active || len(domain.Id) != 32 {
			continue
		}
		intent := new(SettlementDomainLifecycleIntent)
		if found, readErr := c.read(KeyForSettlementDomainLifecycleIntent(domain.Id), intent); readErr != nil {
			return nil, readErr
		} else if !found || intent.Action != "abandon" || intent.ExpiresAtEpoch < clock.CurrentEpoch {
			continue
		}
		deactivated := new(ReplayMarker)
		if found, readErr := c.read(KeyForSettlementDomainDeactivationEpoch(domain.Id), deactivated); readErr != nil {
			return nil, readErr
		} else if !found {
			continue
		}
		deactivationEpoch, valid := settlementDomainDeactivationEpoch(deactivated)
		if !valid || clock.CurrentEpoch < deactivationEpoch || clock.CurrentEpoch-deactivationEpoch < emergencyDomainAbandonmentDelayEpochs {
			continue
		}
		message := &MessageSubmitQuorumSignature{
			ProofKind: "settlement-domain-abandonment", ValidatorSetId: clock.ValidatorSetId,
			SettlementDomainId: append([]byte(nil), domain.Id...), HandoffGeneration: append([]byte(nil), intent.DeactivationGeneration...),
			LifecycleIntentId: append([]byte(nil), intent.Id...), Epoch: deactivationEpoch, ControlBlockNumber: clock.CurrentEpoch,
		}
		message.Digest = hashFields(
			[]byte("takusen:settlement-domain-abandonment"), domain.Id, uint64Bytes(clock.ValidatorSetId),
			intent.DeactivationGeneration, intent.Id, uint64Bytes(deactivationEpoch), uint64Bytes(clock.CurrentEpoch),
		)
		message.Message = append([]byte(nil), message.Digest...)
		message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
		payload, marshalErr := Marshal(message)
		if marshalErr != nil {
			return nil, marshalErr
		}
		appendCandidate(&AuxiliaryCandidate{Kind: message.ProofKind, Key: append([]byte(nil), domain.Id...), Digest: append([]byte(nil), message.Digest...), Payload: payload})
	}

	for _, domain := range params.SettlementDomains {
		if len(result) == maxNativeAuxiliaryCandidates || domain == nil || domain.Active || len(domain.Id) != 32 {
			continue
		}
		intent := new(SettlementDomainLifecycleIntent)
		if found, readErr := c.read(KeyForSettlementDomainLifecycleIntent(domain.Id), intent); readErr != nil {
			return nil, readErr
		} else if !found || intent.ExpiresAtEpoch < clock.CurrentEpoch || intent.Action != "retire" && intent.Action != "cancel" {
			continue
		}
		readinessKind, authorizationKind := "settlement-domain-retirement-readiness", "settlement-domain-retirement-action"
		if intent.Action == "cancel" {
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
		message := &MessageSubmitQuorumSignature{
			ProofKind: authorizationKind, ValidatorSetId: clock.ValidatorSetId, Digest: append([]byte(nil), readiness.Digest...),
			Message: append([]byte(nil), readiness.Digest...), SettlementDomainId: append([]byte(nil), domain.Id...),
			RotationNonce: readiness.RotationNonce, HandoffGeneration: append([]byte(nil), intent.DeactivationGeneration...),
			HandoffTimestamp: readiness.HandoffTimestamp, ControlBlockNumber: readiness.ControlBlockNumber,
			ControlBlockHash: append([]byte(nil), readiness.ControlBlockHash...), LifecycleIntentId: append([]byte(nil), intent.Id...),
		}
		message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
		payload, marshalErr := Marshal(message)
		if marshalErr != nil {
			return nil, marshalErr
		}
		key := hashFields(domain.Id, uint64Bytes(message.RotationNonce), message.HandoffGeneration, message.LifecycleIntentId)
		appendCandidate(&AuxiliaryCandidate{Kind: authorizationKind, Key: key, Digest: append([]byte(nil), message.Digest...), Payload: payload})
	}

	// Timeout discovery is bounded per block. The same earliest expired facts
	// remain candidates until certified, after which their request state changes
	// and the next bounded page can progress.
	requests, err := c.rangeReadPage(RequestPrefix(), nil, 5000)
	if err != nil {
		return nil, err
	}
	for _, entry := range requests {
		if len(result) == maxNativeAuxiliaryCandidates {
			break
		}
		request := new(RequestRecord)
		if Unmarshal(entry.Value, request) != nil || request.Status != "authorized" {
			continue
		}
		for _, assignment := range request.Assignments {
			if len(result) == maxNativeAuxiliaryCandidates {
				break
			}
			if assignment == nil || assignment.Completed || assignment.Attempt == ^uint32(0) || assignment.DeadlineHeight == 0 || height <= assignment.DeadlineHeight ||
				params.ExecutionTimeoutBlocks == 0 ||
				height > ^uint64(0)-params.ExecutionTimeoutBlocks {
				continue
			}
			message := &MessageReassignRequest{RequestId: request.RequestId, Model: assignment.Model, NewDeadlineHeight: height + params.ExecutionTimeoutBlocks}
			payload, marshalErr := Marshal(message)
			if marshalErr != nil {
				return nil, marshalErr
			}
			attempt := assignment.Attempt + 1
			key := hashFields([]byte(request.RequestId), []byte(assignment.Model), uint32Bytes(attempt))
			appendCandidate(&AuxiliaryCandidate{Kind: "native-reassignment", Key: key, Digest: reassignmentSubject(message, attempt), Payload: payload})
		}
	}
	return result, nil
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

func (c *Contract) applyNativeAuxiliaryCertificate(height uint64, candidate *AuxiliaryCandidate, certificate *ConsensusCertificate, records map[string]proto.Message) bool {
	if strings.HasPrefix(candidate.Kind, "evm-observation/") {
		return c.applyEVMObservationCertificate(height, candidate, certificate, records)
	}
	switch candidate.Kind {
	case "epoch-rewards":
		authorization := new(EpochAuthorization)
		if json.Unmarshal(candidate.Payload, authorization) != nil || authorization.Status != "authorized" ||
			len(candidate.Key) != 8 || authorization.Epoch != bytesToUint64(candidate.Key) ||
			!bytes.Equal(candidate.Digest, authorization.CanonicalChainDigest) {
			return false
		}
	case "bridge-release":
		burn := new(BridgeBurn)
		if json.Unmarshal(candidate.Payload, burn) != nil || burn.Status != "pending_release" ||
			!bytes.Equal(candidate.Key, burn.BurnId) || !bytes.Equal(candidate.Digest, burn.CanonicalChainDigest) {
			return false
		}
	case "settlement":
		batch := new(certifiedSettlementBatch)
		if json.Unmarshal(candidate.Payload, batch) != nil || batch.ValidatorSetID != certificate.ValidatorSetId ||
			len(batch.Requests) != 1 || batch.Digest != "0x"+hex.EncodeToString(candidate.Digest) {
			return false
		}
	case "native-reassignment":
		message := new(MessageReassignRequest)
		if Unmarshal(candidate.Payload, message) != nil || len(message.ObserverAddress) != 0 {
			return false
		}
		request := new(RequestRecord)
		if found, err := c.read(KeyForRequest(message.RequestId), request); err != nil || !found {
			return false
		}
		assignment := findAssignment(request, message.Model)
		if assignment == nil || !bytes.Equal(candidate.Digest, reassignmentSubject(message, assignment.Attempt+1)) {
			return false
		}
		if response := c.deliverReassignRequestWithCertificate(height, message, true); response.Error != nil {
			return false
		}
		return true
	case "settlement-domain-abandonment":
		message := new(MessageSubmitQuorumSignature)
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
		message := new(MessageSubmitQuorumSignature)
		if Unmarshal(candidate.Payload, message) != nil || message.ProofKind != candidate.Kind ||
			message.ValidatorSetId != certificate.ValidatorSetId || !bytes.Equal(candidate.Digest, message.Digest) ||
			!bytes.Equal(candidate.Key, hashFields(message.SettlementDomainId, uint64Bytes(message.RotationNonce), message.HandoffGeneration, message.LifecycleIntentId)) {
			return false
		}
		intent := new(SettlementDomainLifecycleIntent)
		found, readErr := c.read(KeyForSettlementDomainLifecycleIntent(message.SettlementDomainId), intent)
		readinessKind, expectedAction := "settlement-domain-retirement-readiness", "retire"
		if candidate.Kind == "settlement-domain-retirement-cancellation" {
			readinessKind, expectedAction = "settlement-domain-retirement-cancellation-readiness", "cancel"
		}
		readiness := new(QuorumProof)
		foundReadiness, readinessErr := c.read(KeyForNativeAuthorizationIntent(readinessKind, message.SettlementDomainId), readiness)
		params, paramsErr := c.currentProtocolParams()
		if paramsErr != nil {
			return false
		}
		clock, clockErr := c.currentEpochClock(params)
		if readErr != nil || !found || readinessErr != nil || !foundReadiness || clockErr != nil ||
			intent.Action != expectedAction || intent.ExpiresAtEpoch < clock.CurrentEpoch || message.HandoffTimestamp <= clock.ConsensusTimeSeconds ||
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
	default:
		return true
	}
	proof := auxiliaryProofRecord(height, candidate, certificate)
	records[string(KeyForQuorumProof(proof.ProofId))] = proof
	return true
}

func (c *Contract) persistCertifiedNativeAbandonment(height uint64, message *MessageSubmitQuorumSignature, certificate *ConsensusCertificate, records map[string]proto.Message) bool {
	params, err := c.currentProtocolParams()
	if err != nil {
		return false
	}
	domain, domainErr := settlementDomain(params, message.SettlementDomainId, false)
	clock, clockErr := c.currentEpochClock(params)
	intent := new(SettlementDomainLifecycleIntent)
	foundIntent, intentErr := c.read(KeyForSettlementDomainLifecycleIntent(message.SettlementDomainId), intent)
	deactivated := new(ReplayMarker)
	foundDeactivation, deactivationErr := c.read(KeyForSettlementDomainDeactivationEpoch(message.SettlementDomainId), deactivated)
	deactivationEpoch, validEpoch := settlementDomainDeactivationEpoch(deactivated)
	if domainErr != nil || domain.Active || clockErr != nil || intentErr != nil || !foundIntent || deactivationErr != nil || !foundDeactivation ||
		intent.Action != "abandon" || intent.ExpiresAtEpoch < clock.CurrentEpoch || !validEpoch || message.Epoch != deactivationEpoch ||
		clock.CurrentEpoch != message.ControlBlockNumber || clock.CurrentEpoch < deactivationEpoch || clock.CurrentEpoch-deactivationEpoch < emergencyDomainAbandonmentDelayEpochs ||
		!bytes.Equal(intent.Id, message.LifecycleIntentId) || !bytes.Equal(intent.DeactivationGeneration, message.HandoffGeneration) {
		return false
	}
	expected := hashFields([]byte("takusen:settlement-domain-abandonment"), message.SettlementDomainId, uint64Bytes(clock.ValidatorSetId), message.HandoffGeneration, message.LifecycleIntentId, uint64Bytes(deactivationEpoch), uint64Bytes(clock.CurrentEpoch))
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
	records[string(KeyForSettlementDomainRetirement(message.SettlementDomainId))] = &ReplayMarker{Id: proofID}
	return true
}

func candidateDigest(message *MessageSubmitQuorumSignature) []byte { return message.Digest }

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
		message := new(MessageObserveAuthorization)
		if Unmarshal(observation.Message, message) != nil || len(message.ObserverAddress) != 0 || message.DirectEoa ||
			!bytes.Equal(message.SettlementDomainId, observation.SettlementDomainID) ||
			message.AuthorizationChainBlockNumber != observation.BlockNumber || !bytes.Equal(message.AuthorizationChainBlockHash, observation.BlockHash) {
			return false
		}
		return apply(authorizationSubject(message), []byte(message.RequestId), func() *PluginDeliverResponse {
			return c.deliverObserveAuthorizationCertified(height, message, true)
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
		message := new(MessageFinalizeRequests)
		if Unmarshal(observation.Message, message) != nil || len(message.ObserverAddress) != 0 || len(message.Requests) == 0 {
			return false
		}
		for _, request := range message.Requests {
			if request == nil || !bytes.Equal(request.SettlementDomainId, observation.SettlementDomainID) {
				return false
			}
		}
		claim := hashFields(message.Requests[0].SettlementTxHash)
		return apply(settlementBatchSubject(message.Requests), claim, func() *PluginDeliverResponse { return c.deliverFinalizeRequestsConsensus(height, message) })
	case "validator-set-rotation-queued", "validator-set-rotation-cancelled", "validator-set-rotation-absent",
		"settlement-domain-authority", "settlement-domain-retirement-readiness", "settlement-domain-retirement-cancellation-readiness",
		"settlement-domain-retirement-cancelled", "settlement-domain-retired":
		message := new(MessageSubmitQuorumSignature)
		if Unmarshal(observation.Message, message) != nil || message.ProofKind != kind ||
			!bytes.Equal(message.SettlementDomainId, observation.SettlementDomainID) ||
			(kind != "settlement-domain-retired" && kind != "settlement-domain-retirement-cancelled" && message.ValidatorSetId != certificate.ValidatorSetId) {
			return false
		}
		if (kind == "settlement-domain-authority" || strings.HasPrefix(kind, "settlement-domain-retirement")) &&
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

func (c *Contract) persistCertifiedEVMControlEvidence(height uint64, message *MessageSubmitQuorumSignature, certificate *ConsensusCertificate, records map[string]proto.Message) bool {
	if message.ProofKind == "validator-set-rotation-queued" || message.ProofKind == "validator-set-rotation-cancelled" || message.ProofKind == "validator-set-rotation-absent" {
		clock, err := c.currentEpochClockFromState()
		if err != nil || !clock.ValidatorHandoffPrepared || !handoffIncludesDomain(clock, message.SettlementDomainId) ||
			message.ValidatorSetId != clock.ValidatorSetId || message.NewValidatorSetId != clock.ValidatorSetId+1 ||
			!bytes.Equal(message.HandoffGeneration, validatorHandoffGeneration(clock)) || message.HandoffTimestamp != clock.ValidatorHandoffTimestamp {
			return false
		}
		if (message.ProofKind == "validator-set-rotation-cancelled" || message.ProofKind == "validator-set-rotation-absent") && !clock.ValidatorHandoffCancelling {
			return false
		}
	}
	if message.ProofKind == "settlement-domain-retirement-readiness" || message.ProofKind == "settlement-domain-retirement-cancellation-readiness" {
		params, err := c.currentProtocolParams()
		if err != nil {
			return false
		}
		clock, clockErr := c.currentEpochClock(params)
		domain, domainErr := settlementDomain(params, message.SettlementDomainId, false)
		intent := new(SettlementDomainLifecycleIntent)
		found, intentErr := c.read(KeyForSettlementDomainLifecycleIntent(message.SettlementDomainId), intent)
		expectedAction := "retire"
		if message.ProofKind == "settlement-domain-retirement-cancellation-readiness" {
			expectedAction = "cancel"
		}
		if clockErr != nil || domainErr != nil || domain.Active || intentErr != nil || !found ||
			intent.Action != expectedAction || intent.ExpiresAtEpoch < clock.CurrentEpoch || message.RotationNonce == 0 ||
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
		intent := new(SettlementDomainLifecycleIntent)
		found, intentErr := c.read(KeyForSettlementDomainLifecycleIntent(message.SettlementDomainId), intent)
		expectedAction := "retire"
		if message.ProofKind == "settlement-domain-retirement-cancelled" {
			expectedAction = "cancel"
		}
		if domainErr != nil || domain.Active || intentErr != nil || !found || intent.Action != expectedAction ||
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
	records[string(KeyForQuorumProof(proofID))] = proof
	switch message.ProofKind {
	case "validator-set-rotation-queued":
		records[string(KeyForQueuedRotationIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: proofID}
	case "validator-set-rotation-cancelled", "validator-set-rotation-absent":
		records[string(KeyForRotationResolutionIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: proofID}
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
	case "settlement-domain-retired":
		records[string(KeyForSettlementDomainRetirement(message.SettlementDomainId))] = &ReplayMarker{Id: proofID}
	}
	return true
}
