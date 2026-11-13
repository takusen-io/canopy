package contract

import (
	"bytes"
	"encoding/hex"
	"math/big"
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
	"validator-set-rotation-queued":             true,
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
	if baseKind == "validator-set-rotation-queued" && len(message.SettlementDomainId) != 32 {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("validator-set proof is missing its settlement domain")}
	}
	var handoffClock *EpochClock
	if baseKind == "validator-set-rotation-queued" || baseKind == "validator-set-rotation-cancelled" ||
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
	if baseKind == "validator-set-rotation-absent" {
		ready, readyErr := c.validatorHandoffReady(handoffClock)
		if readyErr != nil {
			return &PluginDeliverResponse{Error: readyErr}
		}
		if ready || !handoffClock.ValidatorHandoffCancelling {
			return &PluginDeliverResponse{Error: ErrUnauthorized("validator rotation resolution is not authorized by native abort consensus")}
		}
	}
	if baseKind == "validator-set-rotation-cancelled" &&
		(message.NewValidatorSetId != message.ValidatorSetId+1 || message.RotationNonce == 0 || len(message.SettlementDomainId) != 32 ||
			len(message.HandoffGeneration) != 32 || message.HandoffTimestamp == 0) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("invalid finalized validator-set cancellation metadata")}
	}
	if baseKind == "validator-set-rotation-cancelled" && !handoffClock.ValidatorHandoffCancelling {
		return &PluginDeliverResponse{Error: ErrUnauthorized("validator rotation cancellation is not authorized by native abort consensus")}
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
	var rotationClaimKey []byte
	var rotationClaim *Observation
	if baseKind == "validator-set-rotation-queued" {
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
	sortValidatorsByConsensusOrder(validators)
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
		if baseKind == "validator-set-rotation-queued" {
			records[string(KeyForQueuedRotationIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
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
		if baseKind == "validator-set-rotation-cancelled" {
			deletes = append(deletes, KeyForQueuedRotationIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))
			records[string(KeyForRotationResolutionIndex(message.SettlementDomainId, message.ValidatorSetId, message.NewValidatorSetId))] = &ReplayMarker{Id: append([]byte(nil), message.ProofId...)}
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
	sortValidatorsByConsensusOrder(validators)
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
