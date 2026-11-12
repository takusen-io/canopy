package contract

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"sort"
	"strings"

	"github.com/drand/kyber"
	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bdn"
	kilicbls "github.com/kilic/bls12-381"
	"google.golang.org/protobuf/proto"
)

const bdnSignatureSize = 96
const emergencyDomainAbandonmentDelayEpochs uint64 = 168

var allowedProofKinds = map[string]bool{
	"settlement":                                true,
	"request-finalization":                      true,
	"bridge-release":                            true,
	"epoch-rewards":                             true,
	"validator-set-rotation":                    true,
	"validator-set-rotation-queued":             true,
	"validator-set-rotation-cancellation":       true,
	"validator-set-rotation-cancelled":          true,
	"validator-set-rotation-absent":             true,
	"settlement-domain-authority":               true,
	"settlement-domain-retirement-action":       true,
	"settlement-domain-retirement-cancellation": true,
	"settlement-domain-retirement-cancelled":    true,
	"settlement-domain-retired":                 true,
	"settlement-domain-abandonment":             true,
	"governance-action":                         true,
}

func quorumProofID(kind string, setID uint64, digest []byte) []byte {
	return hashFields([]byte("takusen:evm-quorum-proof"), []byte(kind), uint64Bytes(setID), digest)
}

func (c *Contract) deliverSubmitQuorumSignature(height uint64, message *MessageSubmitQuorumSignature) *PluginDeliverResponse {
	baseKind := strings.SplitN(message.ProofKind, "@", 2)[0]
	if !allowedProofKinds[baseKind] {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("unsupported quorum proof kind")}
	}
	if len(message.Digest) != 32 || !bytes.Equal(message.Message, message.Digest) ||
		!bytes.Equal(message.ProofId, quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("quorum proof identity does not match its signed digest")}
	}
	completed := new(QuorumProof)
	if found, err := c.read(KeyForQuorumProof(message.ProofId), completed); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("quorum proof already finalized")}
	}

	snapshot, err := c.activeValidatorSnapshot()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if message.ValidatorSetId != snapshot.validatorSetID {
		return &PluginDeliverResponse{Error: ErrUnauthorized("quorum signature does not use the active validator snapshot")}
	}
	validatorsByAddress, totalWeight := snapshot.validators, snapshot.totalStake
	observer, ok := validatorsByAddress[hex.EncodeToString(message.ObserverAddress)]
	if !ok {
		return &PluginDeliverResponse{Error: ErrUnauthorized("quorum signer is not an active validator")}
	}
	publicKey, cryptoErr := bdnPublicKey(observer.PublicKey)
	if cryptoErr != nil || bdnScheme().Verify(publicKey, message.Message, message.Signature) != nil {
		return &PluginDeliverResponse{Error: ErrCrypto("invalid validator BDN signature share")}
	}
	if (baseKind == "validator-set-rotation" || baseKind == "validator-set-rotation-queued") && len(message.SettlementDomainId) != 32 {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("validator-set proof is missing its settlement domain")}
	}
	var handoffClock *EpochClock
	if baseKind == "validator-set-rotation" || baseKind == "validator-set-rotation-queued" ||
		baseKind == "validator-set-rotation-cancellation" || baseKind == "validator-set-rotation-cancelled" ||
		baseKind == "validator-set-rotation-absent" {
		clock, clockErr := c.currentEpochClockFromState()
		if clockErr != nil {
			return &PluginDeliverResponse{Error: clockErr}
		}
		if !handoffIncludesDomain(clock, message.SettlementDomainId) {
			return &PluginDeliverResponse{Error: ErrUnauthorized("settlement domain is not in the prepared handoff snapshot")}
		}
		if !bytes.Equal(message.HandoffGeneration, validatorHandoffGeneration(clock)) ||
			message.HandoffTimestamp != clock.ValidatorHandoffTimestamp {
			return &PluginDeliverResponse{Error: ErrConflict("validator proof does not match the prepared handoff attempt")}
		}
		handoffClock = clock
	}
	if baseKind == "validator-set-rotation-cancelled" || baseKind == "validator-set-rotation-absent" {
		if found, readErr := c.read(KeyForRotationResolutionIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId), new(ReplayMarker)); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found {
			return &PluginDeliverResponse{Error: ErrConflict("validator handoff domain already has a finalized resolution")}
		}
	}
	if baseKind == "validator-set-rotation" &&
		(message.NewValidatorSetId != message.ValidatorSetId+1 || message.RotationNonce == 0 ||
			len(message.ValidatorKeys) < 2 || len(message.ValidatorKeys) != len(message.ValidatorWeights) ||
			len(message.HandoffGeneration) != 32 || message.HandoffTimestamp == 0) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid validator-set rotation metadata")}
	}
	if baseKind == "validator-set-rotation-cancellation" &&
		(message.NewValidatorSetId != message.ValidatorSetId+1 || message.RotationNonce == 0 || len(message.SettlementDomainId) != 32 ||
			len(message.HandoffGeneration) != 32 || message.HandoffTimestamp == 0) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid validator-set rotation cancellation metadata")}
	}
	if baseKind == "validator-set-rotation-cancellation" || baseKind == "validator-set-rotation-absent" {
		ready, readyErr := c.validatorHandoffReady(handoffClock)
		if readyErr != nil {
			return &PluginDeliverResponse{Error: readyErr}
		}
		if ready || !handoffCancellationWindowOpen(handoffClock) {
			return &PluginDeliverResponse{Error: ErrUnauthorized("validator rotation resolution is not authorized by native abort consensus")}
		}
	}
	if baseKind == "validator-set-rotation-cancelled" &&
		(message.NewValidatorSetId != message.ValidatorSetId+1 || message.RotationNonce == 0 || len(message.SettlementDomainId) != 32 ||
			len(message.HandoffGeneration) != 32 || message.HandoffTimestamp == 0) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid finalized validator-set cancellation metadata")}
	}
	if baseKind == "validator-set-rotation-absent" &&
		(message.NewValidatorSetId != message.ValidatorSetId+1 || message.RotationNonce == 0 || len(message.SettlementDomainId) != 32 ||
			len(message.HandoffGeneration) != 32 || message.HandoffTimestamp == 0 || message.ControlBlockNumber == 0 || len(message.ControlBlockHash) != 32) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid finalized validator-set absence metadata")}
	}
	if baseKind == "validator-set-rotation-absent" {
		expected := hashFields(
			[]byte("takusen:validator-set-rotation-absent"), message.SettlementDomainId,
			uint64Bytes(message.ValidatorSetId), uint64Bytes(message.NewValidatorSetId), uint64Bytes(message.RotationNonce),
			message.HandoffGeneration, uint64Bytes(message.HandoffTimestamp), uint64Bytes(message.ControlBlockNumber), message.ControlBlockHash,
		)
		if !bytes.Equal(message.Digest, expected) {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("validator-set absence digest does not match its finalized evidence")}
		}
	}
	if baseKind == "settlement-domain-authority" {
		if len(message.SettlementDomainId) != 32 || message.ControlBlockNumber == 0 || len(message.ControlBlockHash) != 32 ||
			message.ValidatorSetId != snapshot.validatorSetID {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid settlement-domain authority evidence")}
		}
		expected := hashFields(
			[]byte("takusen:settlement-domain-authority"), message.SettlementDomainId,
			uint64Bytes(message.ValidatorSetId), uint64Bytes(message.ControlBlockNumber), message.ControlBlockHash,
		)
		if !bytes.Equal(message.Digest, expected) {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("settlement-domain authority digest does not match its finalized evidence")}
		}
	}
	if baseKind == "settlement-domain-retirement-action" || baseKind == "settlement-domain-retirement-cancellation" ||
		baseKind == "settlement-domain-retirement-cancelled" || baseKind == "settlement-domain-retired" || baseKind == "settlement-domain-abandonment" {
		if len(message.SettlementDomainId) != 32 || message.ValidatorSetId != snapshot.validatorSetID {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid settlement-domain retirement evidence")}
		}
		params, paramsErr := c.currentProtocolParams()
		if paramsErr != nil {
			return &PluginDeliverResponse{Error: paramsErr}
		}
		domain, domainErr := settlementDomain(params, message.SettlementDomainId, false)
		if domainErr != nil || domain.Active {
			return &PluginDeliverResponse{Error: ErrUnauthorized("only governed inactive settlement domains may retire")}
		}
		clock, clockErr := c.currentEpochClock(params)
		if clockErr != nil {
			return &PluginDeliverResponse{Error: clockErr}
		}
		if clock.ValidatorHandoffPrepared || clock.ValidatorHandoffTimestamp != 0 {
			return &PluginDeliverResponse{Error: ErrConflict("settlement-domain retirement cannot overlap a prepared validator handoff")}
		}
		if found, readErr := c.read(KeyForSettlementDomainRetirement(message.SettlementDomainId), new(ReplayMarker)); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found {
			return &PluginDeliverResponse{Error: ErrConflict("settlement domain is already permanently retired")}
		}
		deactivation := new(ReplayMarker)
		if found, readErr := c.read(KeyForSettlementDomainDeactivation(message.SettlementDomainId), deactivation); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || len(deactivation.Id) != 32 || !bytes.Equal(deactivation.Id, message.HandoffGeneration) {
			return &PluginDeliverResponse{Error: ErrConflict("retirement proof does not match the current deactivation generation")}
		}
		intent := new(SettlementDomainLifecycleIntent)
		if found, readErr := c.read(KeyForSettlementDomainLifecycleIntent(message.SettlementDomainId), intent); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || len(message.LifecycleIntentId) != 32 || !bytes.Equal(intent.Id, message.LifecycleIntentId) ||
			!bytes.Equal(intent.SettlementDomainId, message.SettlementDomainId) || !bytes.Equal(intent.DeactivationGeneration, message.HandoffGeneration) {
			return &PluginDeliverResponse{Error: ErrUnauthorized("settlement-domain lifecycle proof lacks its exact governed intent")}
		}
		expectedAction := "abandon"
		if baseKind == "settlement-domain-retirement-action" || baseKind == "settlement-domain-retired" {
			expectedAction = "retire"
		}
		if baseKind == "settlement-domain-retirement-cancellation" || baseKind == "settlement-domain-retirement-cancelled" {
			expectedAction = "cancel"
		}
		if intent.Action != expectedAction {
			return &PluginDeliverResponse{Error: ErrUnauthorized("settlement-domain lifecycle proof uses a different governed action")}
		}
		if (baseKind == "settlement-domain-retirement-action" || baseKind == "settlement-domain-retirement-cancellation" || baseKind == "settlement-domain-abandonment") &&
			intent.ExpiresAtEpoch < clock.CurrentEpoch {
			return &PluginDeliverResponse{Error: ErrUnauthorized("settlement-domain lifecycle intent has expired")}
		}
		if baseKind == "settlement-domain-retirement-action" || baseKind == "settlement-domain-retirement-cancellation" ||
			baseKind == "settlement-domain-retirement-cancelled" || baseKind == "settlement-domain-retired" {
			if message.ControlBlockNumber == 0 || len(message.ControlBlockHash) != 32 {
				return &PluginDeliverResponse{Error: ErrInvalidTransaction("clean retirement requires finalized EVM evidence")}
			}
			if baseKind == "settlement-domain-retired" {
				expected := hashFields(
					[]byte("takusen:settlement-domain-retired"), message.SettlementDomainId,
					uint64Bytes(message.ValidatorSetId), uint64Bytes(message.RotationNonce), message.HandoffGeneration,
					message.LifecycleIntentId, uint64Bytes(message.ControlBlockNumber), message.ControlBlockHash,
				)
				if !bytes.Equal(message.Digest, expected) {
					return &PluginDeliverResponse{Error: ErrInvalidTransaction("settlement-domain retirement digest does not match finalized evidence")}
				}
			}
			if baseKind == "settlement-domain-retirement-cancelled" {
				expected := hashFields(
					[]byte("takusen:settlement-domain-retirement-cancelled"), message.SettlementDomainId,
					uint64Bytes(message.ValidatorSetId), uint64Bytes(message.RotationNonce), message.HandoffGeneration,
					message.LifecycleIntentId, uint64Bytes(message.ControlBlockNumber), message.ControlBlockHash,
				)
				if !bytes.Equal(message.Digest, expected) {
					return &PluginDeliverResponse{Error: ErrInvalidTransaction("retirement cancellation digest does not match finalized evidence")}
				}
			}
			if message.RotationNonce == 0 || (baseKind == "settlement-domain-retirement-action" && message.HandoffTimestamp == 0) {
				return &PluginDeliverResponse{Error: ErrInvalidTransaction("retirement proof is missing its nonce or validity window")}
			}
		} else {
			deactivated := new(ReplayMarker)
			found, readErr := c.read(KeyForSettlementDomainDeactivationEpoch(message.SettlementDomainId), deactivated)
			deactivationEpoch, valid := settlementDomainDeactivationEpoch(deactivated)
			if readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			}
			if !found || !valid || message.Epoch != deactivationEpoch || message.ControlBlockNumber != clock.CurrentEpoch ||
				clock.CurrentEpoch < deactivationEpoch || clock.CurrentEpoch-deactivationEpoch < emergencyDomainAbandonmentDelayEpochs {
				return &PluginDeliverResponse{Error: ErrUnauthorized("emergency abandonment cooling period has not completed")}
			}
			expected := hashFields(
				[]byte("takusen:settlement-domain-abandonment"), message.SettlementDomainId,
				uint64Bytes(message.ValidatorSetId), message.HandoffGeneration, message.LifecycleIntentId,
				uint64Bytes(deactivationEpoch), uint64Bytes(clock.CurrentEpoch),
			)
			if !bytes.Equal(message.Digest, expected) {
				return &PluginDeliverResponse{Error: ErrInvalidTransaction("settlement-domain abandonment digest does not match native state")}
			}
		}
	}
	if baseKind == "validator-set-rotation-queued" &&
		(message.NewValidatorSetId != message.ValidatorSetId+1 || message.RotationNonce == 0 ||
			len(message.HandoffGeneration) != 32 || message.HandoffTimestamp == 0) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid queued validator-set rotation metadata")}
	}
	if baseKind == "validator-set-rotation" {
		params, paramsErr := c.currentProtocolParams()
		if paramsErr != nil {
			return &PluginDeliverResponse{Error: paramsErr}
		}
		setID, setErr := c.currentValidatorSetID(params)
		if setErr != nil {
			return &PluginDeliverResponse{Error: setErr}
		}
		if message.ValidatorSetId != setID {
			return &PluginDeliverResponse{Error: ErrUnauthorized("rotation does not use the active validator set")}
		}
		if rotationErr := c.validatePreparedRotation(message, params); rotationErr != nil {
			return &PluginDeliverResponse{Error: rotationErr}
		}
	}

	var rotationClaimKey []byte
	var rotationClaim *Observation
	if baseKind == "validator-set-rotation" || baseKind == "validator-set-rotation-queued" {
		claim := hashFields(
			[]byte("takusen:validator-set-rotation-claim"), []byte(baseKind),
			message.SettlementDomainId,
			uint64Bytes(message.ValidatorSetId), uint64Bytes(message.NewValidatorSetId), uint64Bytes(message.RotationNonce),
		)
		subject := hashFields(
			[]byte("takusen:validator-set-rotation-subject"), []byte(baseKind), message.Digest,
		)
		rotationClaimKey = KeyForObservationClaim(observationValidatorRotation, snapshot.validatorSetID, snapshot.epoch, claim, message.ObserverAddress)
		prior := new(Observation)
		if found, readErr := c.read(rotationClaimKey, prior); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found && !bytes.Equal(prior.SubjectHash, subject) {
			return &PluginDeliverResponse{Error: ErrConflict("validator signed conflicting validator-set rotations for this epoch")}
		}
		rotationClaim = &Observation{
			SubjectHash: subject, ObserverAddress: append([]byte(nil), message.ObserverAddress...),
			ObservedHeight: height, ClaimHash: claim, ValidatorSetId: snapshot.validatorSetID,
			ObserverWeight: observer.StakedAmount, TotalWeight: snapshot.totalStake, ValidatorEpoch: snapshot.epoch,
		}
	}

	shareKey := KeyForQuorumShare(message.ProofId, message.ObserverAddress)
	prior := new(QuorumSignatureShare)
	if found, readErr := c.read(shareKey, prior); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("validator already submitted this quorum signature")}
	}
	share := &QuorumSignatureShare{
		ProofId: message.ProofId, ObserverAddress: message.ObserverAddress,
		Signature: message.Signature, ObservedHeight: height,
	}
	records := map[string]proto.Message{string(shareKey): share}
	if len(rotationClaimKey) != 0 {
		records[string(rotationClaimKey)] = rotationClaim
	}

	validators := make([]*Validator, 0, len(validatorsByAddress))
	for _, validator := range validatorsByAddress {
		validators = append(validators, validator)
	}
	sort.Slice(validators, func(i, j int) bool {
		return bytes.Compare(validators[i].PublicKey, validators[j].PublicKey) < 0
	})
	shares, readErr := c.rangeRead(QuorumShareProofPrefix(message.ProofId))
	if readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	}
	signatures := map[string][]byte{hex.EncodeToString(message.ObserverAddress): message.Signature}
	for _, entry := range shares {
		stored := new(QuorumSignatureShare)
		if decodeErr := Unmarshal(entry.Value, stored); decodeErr != nil {
			return &PluginDeliverResponse{Error: decodeErr}
		}
		signatures[hex.EncodeToString(stored.ObserverAddress)] = stored.Signature
	}

	var signedWeight uint64
	for _, validator := range validators {
		if _, signed := signatures[hex.EncodeToString(validator.Address)]; signed {
			if ^uint64(0)-signedWeight < validator.StakedAmount {
				return &PluginDeliverResponse{Error: ErrState("signed validator stake overflow")}
			}
			signedWeight += validator.StakedAmount
		}
	}
	left := new(big.Int).Mul(new(big.Int).SetUint64(signedWeight), big.NewInt(3))
	right := new(big.Int).Mul(new(big.Int).SetUint64(totalWeight), big.NewInt(2))
	complete := left.Cmp(right) > 0
	if complete {
		proof, proofErr := buildQuorumProof(height, message, validators, signatures, signedWeight, totalWeight)
		if proofErr != nil {
			return &PluginDeliverResponse{Error: ErrCrypto(proofErr.Error())}
		}
		records[string(KeyForQuorumProof(message.ProofId))] = proof
		if baseKind == "validator-set-rotation" {
			records[string(KeyForRotationProofIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
		}
		if baseKind == "validator-set-rotation-queued" {
			records[string(KeyForQueuedRotationIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
		}
		if baseKind == "validator-set-rotation-cancellation" {
			records[string(KeyForRotationCancellationIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
		}
		if baseKind == "validator-set-rotation-absent" {
			records[string(KeyForRotationResolutionIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
		}
		if baseKind == "settlement-domain-authority" {
			records[string(KeyForSettlementDomainAuthority(message.SettlementDomainId, message.ValidatorSetId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
		}
		if baseKind == "settlement-domain-retired" || baseKind == "settlement-domain-abandonment" {
			records[string(KeyForSettlementDomainRetirement(message.SettlementDomainId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
		}
		if baseKind == "settlement-domain-retirement-cancelled" {
			records[string(KeyForSettlementDomainRetirementCancellation(message.SettlementDomainId, message.HandoffGeneration))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
		}
		delete(records, string(shareKey))
		deletes := make([][]byte, 0, len(shares)+1)
		deletes = append(deletes, shareKey)
		for _, entry := range shares {
			deletes = append(deletes, entry.Key)
		}
		if baseKind == "settlement-domain-retirement-cancelled" || baseKind == "settlement-domain-retired" || baseKind == "settlement-domain-abandonment" {
			deletes = append(deletes, KeyForSettlementDomainLifecycleIntent(message.SettlementDomainId))
		}
		if baseKind == "validator-set-rotation-cancellation" || baseKind == "validator-set-rotation-cancelled" {
			indexKey := KeyForRotationProofIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId)
			marker := new(ReplayMarker)
			if found, readErr := c.read(indexKey, marker); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if !found {
				return &PluginDeliverResponse{Error: ErrNotFound("validator rotation proof index is absent")}
			}
			queued := new(QuorumProof)
			if found, readErr := c.read(KeyForQuorumProof(marker.Id), queued); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if !found || queued.ProofKind != "validator-set-rotation" || queued.ValidatorSetId != message.ValidatorSetId ||
				queued.NewValidatorSetId != message.NewValidatorSetId || queued.RotationNonce != message.RotationNonce ||
				!bytes.Equal(queued.SettlementDomainId, message.SettlementDomainId) {
				return &PluginDeliverResponse{Error: ErrConflict("rotation cancellation does not match the indexed generation")}
			}
			if !bytes.Equal(queued.HandoffGeneration, message.HandoffGeneration) || queued.HandoffTimestamp != message.HandoffTimestamp {
				return &PluginDeliverResponse{Error: ErrConflict("rotation cancellation targets a different handoff attempt")}
			}
			if baseKind == "validator-set-rotation-cancelled" {
				cancellationKey := KeyForRotationCancellationIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId)
				intentMarker := new(ReplayMarker)
				if found, readErr := c.read(cancellationKey, intentMarker); readErr != nil {
					return &PluginDeliverResponse{Error: readErr}
				} else if !found {
					return &PluginDeliverResponse{Error: ErrNotFound("validator rotation cancellation was not authorized")}
				}
				intent := new(QuorumProof)
				if found, readErr := c.read(KeyForQuorumProof(intentMarker.Id), intent); readErr != nil {
					return &PluginDeliverResponse{Error: readErr}
				} else if !found || intent.ProofKind != "validator-set-rotation-cancellation" ||
					intent.RotationNonce != message.RotationNonce || !bytes.Equal(intent.HandoffGeneration, message.HandoffGeneration) ||
					intent.HandoffTimestamp != message.HandoffTimestamp {
					return &PluginDeliverResponse{Error: ErrConflict("finalized cancellation does not match its native authorization")}
				}
				deletes = append(deletes, KeyForQueuedRotationIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId), cancellationKey)
				records[string(KeyForRotationResolutionIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
			}
		}
		if writeErr := c.writeChanges(records, deletes); writeErr != nil {
			return &PluginDeliverResponse{Error: writeErr}
		}
		return &PluginDeliverResponse{}
	}
	if writeErr := c.write(records); writeErr != nil {
		return &PluginDeliverResponse{Error: writeErr}
	}
	return &PluginDeliverResponse{}
}

func buildQuorumProof(height uint64, message *MessageSubmitQuorumSignature, validators []*Validator, signatures map[string][]byte, signedWeight, totalWeight uint64) (*QuorumProof, error) {
	suite := drandbls.NewBLS12381Suite()
	points := make([]kyber.Point, len(validators))
	for i, validator := range validators {
		point, err := bdnPublicKey(validator.PublicKey)
		if err != nil {
			return nil, err
		}
		points[i] = point
	}
	mask, err := sign.NewMask(suite, points, nil)
	if err != nil {
		return nil, err
	}
	partialSignatures := make([][]byte, 0, len(signatures))
	for i, validator := range validators {
		if signature, ok := signatures[hex.EncodeToString(validator.Address)]; ok {
			if err = mask.SetBit(i, true); err != nil {
				return nil, err
			}
			partialSignatures = append(partialSignatures, signature)
		}
	}
	scheme := bdn.NewSchemeOnG2(suite)
	aggregate, err := scheme.AggregateSignatures(partialSignatures, mask)
	if err != nil {
		return nil, err
	}
	aggregatePublicKey, err := scheme.AggregatePublicKeys(mask)
	if err != nil {
		return nil, err
	}
	aggregateSignature, err := aggregate.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err = scheme.Verify(aggregatePublicKey, message.Message, aggregateSignature); err != nil {
		return nil, err
	}
	eipSignature, err := g2CompressedToEIP2537(aggregateSignature)
	if err != nil {
		return nil, err
	}
	return &QuorumProof{
		ProofKind: message.ProofKind, ProofId: message.ProofId, Digest: message.Digest,
		ValidatorSetId: message.ValidatorSetId, SignerBitmap: mask.Mask(),
		AggregateSignatureEip2537: eipSignature, SignedWeight: signedWeight,
		TotalWeight: totalWeight, CompletedHeight: height,
		NewValidatorSetId:  message.NewValidatorSetId,
		RotationNonce:      message.RotationNonce,
		SettlementDomainId: append([]byte(nil), message.SettlementDomainId...),
		HandoffGeneration:  append([]byte(nil), message.HandoffGeneration...),
		HandoffTimestamp:   message.HandoffTimestamp,
		ControlBlockNumber: message.ControlBlockNumber,
		ControlBlockHash:   append([]byte(nil), message.ControlBlockHash...),
		LifecycleIntentId:  append([]byte(nil), message.LifecycleIntentId...),
	}, nil
}

func (c *Contract) validatePreparedRotation(message *MessageSubmitQuorumSignature, params *ProtocolParams) *PluginError {
	clock, err := c.currentEpochClock(params)
	if err != nil {
		return err
	}
	if clock.CurrentEpoch == ^uint64(0) {
		return ErrState("validator epoch overflow")
	}
	if !clock.ValidatorHandoffPrepared || clock.ValidatorHandoffTimestamp == 0 ||
		message.HandoffTimestamp != clock.ValidatorHandoffTimestamp ||
		!bytes.Equal(message.HandoffGeneration, validatorHandoffGeneration(clock)) {
		return ErrInvalidTransaction("rotation does not match the prepared global handoff")
	}
	entries, err := c.rangeRead(EpochValidatorPrefix(clock.CurrentEpoch + 1))
	if err != nil {
		return err
	}
	validators := make([]*Validator, 0, len(entries))
	var total uint64
	for _, entry := range entries {
		validator := new(Validator)
		if decodeErr := Unmarshal(entry.Value, validator); decodeErr != nil {
			return decodeErr
		}
		if !validAddress(validator.Address) || len(validator.PublicKey) == 0 || validator.StakedAmount == 0 {
			return ErrState("prepared validator snapshot contains an invalid member")
		}
		if ^uint64(0)-total < validator.StakedAmount {
			return ErrState("prepared validator stake overflow")
		}
		total += validator.StakedAmount
		validators = append(validators, validator)
	}
	if len(validators) < 2 || total == 0 || len(validators) != len(message.ValidatorKeys) {
		return ErrInvalidTransaction("rotation does not match the prepared validator set")
	}
	sort.Slice(validators, func(i, j int) bool { return bytes.Compare(validators[i].PublicKey, validators[j].PublicKey) < 0 })
	points := make([]kyber.Point, len(validators))
	for index, validator := range validators {
		point, pointErr := bdnPublicKey(validator.PublicKey)
		if pointErr != nil {
			return ErrCrypto("prepared validator public key is invalid")
		}
		points[index] = point
	}
	mask, maskErr := sign.NewMask(drandbls.NewBLS12381Suite(), points, nil)
	if maskErr != nil {
		return ErrCrypto("prepared validator mask is invalid")
	}
	scheme := bdnScheme()
	for index, validator := range validators {
		if mask.SetBit(index, true) != nil {
			return ErrCrypto("prepared validator mask is invalid")
		}
		weighted, aggregateErr := scheme.AggregatePublicKeys(mask)
		if aggregateErr != nil {
			return ErrCrypto("prepared validator key aggregation failed")
		}
		compressed, marshalErr := weighted.MarshalBinary()
		if marshalErr != nil {
			return ErrCrypto("prepared validator key encoding failed")
		}
		if mask.SetMask(make([]byte, len(mask.Mask()))) != nil {
			return ErrCrypto("prepared validator mask reset failed")
		}
		uncompressed, conversionErr := g1CompressedToEIP2537(compressed)
		if conversionErr != nil {
			return ErrCrypto("prepared validator key conversion failed")
		}
		if !bytes.Equal(uncompressed, message.ValidatorKeys[index]) || validator.StakedAmount != message.ValidatorWeights[index] {
			return ErrInvalidTransaction("rotation does not match the prepared validator set")
		}
	}
	return nil
}

func bdnScheme() *bdn.Scheme { return bdn.NewSchemeOnG2(drandbls.NewBLS12381Suite()) }

func bdnPublicKey(compressed []byte) (kyber.Point, error) {
	point := drandbls.NewBLS12381Suite().G1().Point()
	if err := point.UnmarshalBinary(compressed); err != nil {
		return nil, err
	}
	return point, nil
}

func (c *Contract) verifyValidatorCertificate(digest []byte, validatorSetID uint64, bitmap, aggregate []byte) *PluginError {
	params, err := c.currentProtocolParams()
	if err != nil {
		return err
	}
	currentSetID, setErr := c.currentValidatorSetID(params)
	if setErr != nil {
		return setErr
	}
	if validatorSetID == 0 || validatorSetID != currentSetID || len(aggregate) != bdnSignatureSize {
		return ErrUnauthorized("certificate does not use the governed validator set")
	}
	validatorsByAddress, totalWeight, stateErr := c.activeValidators()
	if stateErr != nil {
		return stateErr
	}
	validators := make([]*Validator, 0, len(validatorsByAddress))
	for _, validator := range validatorsByAddress {
		validators = append(validators, validator)
	}
	sort.Slice(validators, func(i, j int) bool { return bytes.Compare(validators[i].PublicKey, validators[j].PublicKey) < 0 })
	suite := drandbls.NewBLS12381Suite()
	points := make([]kyber.Point, len(validators))
	for i, validator := range validators {
		point, pointErr := bdnPublicKey(validator.PublicKey)
		if pointErr != nil {
			return ErrCrypto("certificate contains an invalid validator public key")
		}
		points[i] = point
	}
	mask, maskErr := sign.NewMask(suite, points, nil)
	if maskErr != nil || mask.SetMask(bitmap) != nil {
		return ErrCrypto("certificate signer bitmap is invalid")
	}
	var signedWeight uint64
	for i, validator := range validators {
		if bitmap[i/8]&(1<<uint(i&7)) == 0 {
			continue
		}
		if ^uint64(0)-signedWeight < validator.StakedAmount {
			return ErrState("certificate signer stake overflow")
		}
		signedWeight += validator.StakedAmount
	}
	left := new(big.Int).Mul(new(big.Int).SetUint64(signedWeight), big.NewInt(3))
	right := new(big.Int).Mul(new(big.Int).SetUint64(totalWeight), big.NewInt(2))
	if left.Cmp(right) <= 0 {
		return ErrUnauthorized("certificate does not contain strict two-thirds stake")
	}
	aggregatePublicKey, aggregateErr := bdn.NewSchemeOnG2(suite).AggregatePublicKeys(mask)
	if aggregateErr != nil || bdn.NewSchemeOnG2(suite).Verify(aggregatePublicKey, digest, aggregate) != nil {
		return ErrCrypto("certificate aggregate signature is invalid")
	}
	return nil
}

func g2CompressedToEIP2537(compressed []byte) ([]byte, error) {
	g2 := kilicbls.NewG2()
	point, err := g2.FromCompressed(compressed)
	if err != nil {
		return nil, err
	}
	// kilic serializes Fp2 as c1 || c0; EIP-2537 requires c0 || c1,
	// and pads each 48-byte field element to 64 bytes.
	raw := g2.ToUncompressed(point)
	result := make([]byte, 256)
	for coordinate := 0; coordinate < 2; coordinate++ {
		source := coordinate * 96
		target := coordinate * 128
		copy(result[target+16:target+64], raw[source+48:source+96])
		copy(result[target+80:target+128], raw[source:source+48])
	}
	return result, nil
}

func g1CompressedToEIP2537(compressed []byte) ([]byte, error) {
	g1 := kilicbls.NewG1()
	point, err := g1.FromCompressed(compressed)
	if err != nil {
		return nil, err
	}
	raw := g1.ToUncompressed(point)
	result := make([]byte, 128)
	copy(result[16:64], raw[:48])
	copy(result[80:128], raw[48:])
	return result, nil
}
