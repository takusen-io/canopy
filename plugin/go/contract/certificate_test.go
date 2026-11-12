package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"testing"

	"github.com/drand/kyber"
	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bdn"
	"google.golang.org/protobuf/proto"
)

func storeLifecycleIntent(t *testing.T, store *memoryStateStore, domainID, generation []byte, action string, nonce, expiresAtEpoch uint64) []byte {
	t.Helper()
	intentID := settlementDomainLifecycleIntentID(domainID, generation, action, nonce, expiresAtEpoch)
	store.put(t, KeyForSettlementDomainLifecycleIntent(domainID), &SettlementDomainLifecycleIntent{
		Id:                     intentID,
		SettlementDomainId:     append([]byte(nil), domainID...),
		DeactivationGeneration: append([]byte(nil), generation...),
		Action:                 action,
		Nonce:                  nonce,
		ExpiresAtEpoch:         expiresAtEpoch,
	})
	return intentID
}

func TestValidatorCertificateRequiresStrictTwoThirds(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	store.values = make(map[string][]byte)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 5
	store.put(t, KeyForProtocolParams(), params)

	suite := drandbls.NewBLS12381Suite()
	for i := int64(1); i <= 4; i++ {
		private := suite.G1().Scalar().SetInt64(i)
		public := suite.G1().Point().Mul(private, nil)
		encoded, err := public.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		address := append([]byte(nil), digest[:20]...)
		validator := &Validator{
			Address: address, PublicKey: encoded, StakedAmount: 100, Committees: []uint64{1},
		}
		store.put(t, KeyForValidator(address), validator)
		store.put(t, KeyForEpochValidator(1, address), validator)
	}

	// activeValidators are sorted by public key; rebuild keys in that same
	// order so the bitmap and BDN coefficients have one canonical meaning.
	validators, _, stateErr := contract.activeValidators()
	if stateErr != nil {
		t.Fatal(stateErr)
	}
	ordered := make([]*Validator, 0, len(validators))
	for _, validator := range validators {
		ordered = append(ordered, validator)
	}
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i].PublicKey, ordered[j].PublicKey) < 0 })
	kyberPublics := make([]kyber.Point, len(ordered))
	privateByPublic := make(map[string]kyber.Scalar)
	for i := int64(1); i <= 4; i++ {
		private := suite.G1().Scalar().SetInt64(i)
		public := suite.G1().Point().Mul(private, nil)
		encoded, _ := public.MarshalBinary()
		privateByPublic[string(encoded)] = private
	}
	for i, validator := range ordered {
		point, err := bdnPublicKey(validator.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		kyberPublics[i] = point
	}
	mask, err := sign.NewMask(suite, kyberPublics, nil)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("finalization"))
	scheme := bdn.NewSchemeOnG2(suite)
	partials := make([][]byte, 0, 3)
	for i := 0; i < 3; i++ {
		if err = mask.SetBit(i, true); err != nil {
			t.Fatal(err)
		}
		signature, signErr := scheme.Sign(privateByPublic[string(ordered[i].PublicKey)], digest[:])
		if signErr != nil {
			t.Fatal(signErr)
		}
		partials = append(partials, signature)
	}
	aggregate, err := scheme.AggregateSignatures(partials, mask)
	if err != nil {
		t.Fatal(err)
	}
	encodedAggregate, _ := aggregate.MarshalBinary()
	if certErr := contract.verifyValidatorCertificate(digest[:], 5, mask.Mask(), encodedAggregate); certErr != nil {
		t.Fatal(certErr)
	}
	mask.SetBit(2, false)
	if certErr := contract.verifyValidatorCertificate(digest[:], 5, mask.Mask(), encodedAggregate); certErr == nil {
		t.Fatal("accepted a certificate without strict two-thirds stake")
	}
}

func TestQuorumSignatureRejectsStaleValidatorSnapshotBeforeAccumulation(t *testing.T) {
	contract, _, first, _ := newMemoryContract(t)
	digest := sha256.Sum256([]byte("stale validator snapshot"))
	message := &MessageSubmitQuorumSignature{
		ProofKind: "settlement", ProofId: quorumProofID("settlement", 99, digest[:]),
		Digest: digest[:], Message: digest[:], ValidatorSetId: 99,
		ObserverAddress: first, Signature: bytes.Repeat([]byte{1}, bdnSignatureSize),
	}
	response := contract.deliverSubmitQuorumSignature(10, message)
	if response.Error == nil {
		t.Fatal("stale validator-set share was accepted for accumulation")
	}
}

func TestSettlementDomainAuthorityMarkerRequiresStrictQuorum(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	store.values = make(map[string][]byte)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 5
	store.put(t, KeyForProtocolParams(), params)
	suite := drandbls.NewBLS12381Suite()
	scheme := bdn.NewSchemeOnG2(suite)
	type signer struct {
		address []byte
		private kyber.Scalar
	}
	signers := make([]signer, 2)
	for index := range signers {
		private := suite.G1().Scalar().SetInt64(int64(index + 1))
		public := suite.G1().Point().Mul(private, nil)
		encoded, err := public.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(encoded)
		address := append([]byte(nil), hash[:20]...)
		validator := &Validator{Address: address, PublicKey: encoded, StakedAmount: 100, Committees: []uint64{1}}
		store.put(t, KeyForEpochValidator(1, address), validator)
		signers[index] = signer{address: address, private: private}
	}
	domainID := params.SettlementDomains[0].Id
	blockHash := bytes.Repeat([]byte{0xa7}, 32)
	digest := hashFields([]byte("takusen:settlement-domain-authority"), domainID, uint64Bytes(5), uint64Bytes(99), blockHash)
	message := &MessageSubmitQuorumSignature{
		ProofKind: "settlement-domain-authority", Digest: digest, Message: digest, ValidatorSetId: 5,
		SettlementDomainId: domainID, ControlBlockNumber: 99, ControlBlockHash: blockHash,
	}
	message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
	for index, signer := range signers {
		message.ObserverAddress = signer.address
		signature, err := scheme.Sign(signer.private, digest)
		if err != nil {
			t.Fatal(err)
		}
		message.Signature = signature
		if response := contract.deliverSubmitQuorumSignature(uint64(20+index), message); response.Error != nil {
			t.Fatal(response.Error)
		}
		_, marked := store.values[string(KeyForSettlementDomainAuthority(domainID, 5))]
		if marked != (index == len(signers)-1) {
			t.Fatalf("authority marker quorum state after share %d = %v", index, marked)
		}
	}
}

func TestEmergencyDomainAbandonmentRequiresCoolingPeriodAndStrictQuorum(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	store.values = make(map[string][]byte)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 5
	retiring := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	retiring.ChainId = 56
	retiring.Network = "eip155:56"
	retiring.TokenAddress = bytes.Repeat([]byte{0xb1}, 20)
	retiring.EscrowAddress = bytes.Repeat([]byte{0xb2}, 20)
	retiring.VerifierAddress = bytes.Repeat([]byte{0xb3}, 20)
	retiring.FoundationTreasuryAddress = bytes.Repeat([]byte{0xb4}, 20)
	retiring.Id = keccak(abiUint64(retiring.ChainId), abiAddress(retiring.TokenAddress), abiAddress(retiring.EscrowAddress), abiAddress(retiring.VerifierAddress))
	retiring.Active = false
	params.SettlementDomains = append(params.SettlementDomains, retiring)
	store.put(t, KeyForProtocolParams(), params)
	deactivationGeneration := bytes.Repeat([]byte{0xae}, 32)
	store.put(t, KeyForSettlementDomainDeactivation(retiring.Id), &ReplayMarker{Id: deactivationGeneration})
	store.put(t, KeyForSettlementDomainDeactivationEpoch(retiring.Id), &ReplayMarker{Id: uint64Bytes(1)})
	clock := &EpochClock{CurrentEpoch: 168, StartHeight: 1, EndHeight: params.EpochBlocks, ValidatorSetId: 5, EpochBlocks: params.EpochBlocks}
	store.put(t, KeyForEpochClock(), clock)
	intentID := storeLifecycleIntent(t, store, retiring.Id, deactivationGeneration, "abandon", 1, 170)

	suite := drandbls.NewBLS12381Suite()
	scheme := bdn.NewSchemeOnG2(suite)
	type signer struct {
		address []byte
		private kyber.Scalar
	}
	signers := make([]signer, 2)
	for index := range signers {
		private := suite.G1().Scalar().SetInt64(int64(index + 1))
		public := suite.G1().Point().Mul(private, nil)
		encoded, err := public.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(encoded)
		address := append([]byte(nil), hash[:20]...)
		validator := &Validator{Address: address, PublicKey: encoded, StakedAmount: 100, Committees: []uint64{1}}
		store.put(t, KeyForEpochValidator(168, address), validator)
		signers[index] = signer{address: address, private: private}
	}
	digest := hashFields([]byte("takusen:settlement-domain-abandonment"), retiring.Id, uint64Bytes(5), deactivationGeneration, intentID, uint64Bytes(1), uint64Bytes(168))
	message := &MessageSubmitQuorumSignature{
		ProofKind: "settlement-domain-abandonment", Digest: digest, Message: digest, ValidatorSetId: 5,
		SettlementDomainId: retiring.Id, Epoch: 1, HandoffGeneration: deactivationGeneration, LifecycleIntentId: intentID, ControlBlockNumber: 168,
	}
	message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
	message.ObserverAddress = signers[0].address
	message.Signature, _ = scheme.Sign(signers[0].private, digest)
	if response := contract.deliverSubmitQuorumSignature(20, message); response.Error == nil {
		t.Fatal("emergency abandonment succeeded before 168 complete inactive epochs")
	}

	clock.CurrentEpoch = 169
	store.put(t, KeyForEpochClock(), clock)
	for _, signer := range signers {
		validator := &Validator{Address: signer.address, PublicKey: nil, StakedAmount: 100, Committees: []uint64{1}}
		// Preserve the exact public key already installed in epoch 168.
		prior := new(Validator)
		if found, err := contract.read(KeyForEpochValidator(168, signer.address), prior); err != nil || !found {
			t.Fatal(err)
		}
		validator.PublicKey = prior.PublicKey
		store.put(t, KeyForEpochValidator(169, signer.address), validator)
	}
	digest = hashFields([]byte("takusen:settlement-domain-abandonment"), retiring.Id, uint64Bytes(5), deactivationGeneration, intentID, uint64Bytes(1), uint64Bytes(169))
	message.Digest, message.Message, message.ControlBlockNumber = digest, digest, 169
	message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, digest)
	for index, signer := range signers {
		message.ObserverAddress = signer.address
		message.Signature, _ = scheme.Sign(signer.private, digest)
		if response := contract.deliverSubmitQuorumSignature(uint64(30+index), message); response.Error != nil {
			t.Fatal(response.Error)
		}
		_, marked := store.values[string(KeyForSettlementDomainRetirement(retiring.Id))]
		if marked != (index == len(signers)-1) {
			t.Fatalf("retirement tombstone quorum state after share %d = %v", index, marked)
		}
	}
}

func TestCleanDomainRetirementMarkerRequiresStrictQuorum(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	store.values = make(map[string][]byte)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 5
	retiring := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	retiring.ChainId = 56
	retiring.Network = "eip155:56"
	retiring.TokenAddress = bytes.Repeat([]byte{0xc1}, 20)
	retiring.EscrowAddress = bytes.Repeat([]byte{0xc2}, 20)
	retiring.VerifierAddress = bytes.Repeat([]byte{0xc3}, 20)
	retiring.FoundationTreasuryAddress = bytes.Repeat([]byte{0xc4}, 20)
	retiring.Id = keccak(abiUint64(retiring.ChainId), abiAddress(retiring.TokenAddress), abiAddress(retiring.EscrowAddress), abiAddress(retiring.VerifierAddress))
	retiring.Active = false
	params.SettlementDomains = append(params.SettlementDomains, retiring)
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEpochClock(), &EpochClock{
		CurrentEpoch: 1, StartHeight: 1, EndHeight: params.EpochBlocks, ValidatorSetId: 5,
		EpochBlocks: params.EpochBlocks,
	})
	deactivationGeneration := bytes.Repeat([]byte{0xce}, 32)
	store.put(t, KeyForSettlementDomainDeactivation(retiring.Id), &ReplayMarker{Id: deactivationGeneration})
	store.put(t, KeyForSettlementDomainDeactivationEpoch(retiring.Id), &ReplayMarker{Id: uint64Bytes(1)})
	intentID := storeLifecycleIntent(t, store, retiring.Id, deactivationGeneration, "retire", 1, 10)

	suite := drandbls.NewBLS12381Suite()
	scheme := bdn.NewSchemeOnG2(suite)
	type signer struct {
		address []byte
		private kyber.Scalar
	}
	signers := make([]signer, 2)
	for index := range signers {
		private := suite.G1().Scalar().SetInt64(int64(index + 1))
		public := suite.G1().Point().Mul(private, nil)
		encoded, err := public.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(encoded)
		address := append([]byte(nil), hash[:20]...)
		store.put(t, KeyForEpochValidator(1, address), &Validator{
			Address: address, PublicKey: encoded, StakedAmount: 100, Committees: []uint64{1},
		})
		signers[index] = signer{address: address, private: private}
	}
	blockHash := bytes.Repeat([]byte{0xd1}, 32)
	digest := hashFields([]byte("takusen:settlement-domain-retired"), retiring.Id, uint64Bytes(5), uint64Bytes(1), deactivationGeneration, intentID, uint64Bytes(99), blockHash)
	message := &MessageSubmitQuorumSignature{
		ProofKind: "settlement-domain-retired", Digest: digest, Message: digest, ValidatorSetId: 5,
		SettlementDomainId: retiring.Id, RotationNonce: 1, HandoffGeneration: deactivationGeneration, LifecycleIntentId: intentID, ControlBlockNumber: 99, ControlBlockHash: blockHash,
	}
	message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, digest)
	wrongIntent := proto.Clone(message).(*MessageSubmitQuorumSignature)
	wrongIntent.LifecycleIntentId = bytes.Repeat([]byte{0xff}, 32)
	wrongIntent.ObserverAddress = signers[0].address
	wrongIntent.Signature, _ = scheme.Sign(signers[0].private, digest)
	if response := contract.deliverSubmitQuorumSignature(19, wrongIntent); response.Error == nil {
		t.Fatal("retirement proof without the exact governed lifecycle intent was accepted")
	}
	for index, signer := range signers {
		message.ObserverAddress = signer.address
		message.Signature, _ = scheme.Sign(signer.private, digest)
		if response := contract.deliverSubmitQuorumSignature(uint64(20+index), message); response.Error != nil {
			t.Fatal(response.Error)
		}
		_, marked := store.values[string(KeyForSettlementDomainRetirement(retiring.Id))]
		if marked != (index == len(signers)-1) {
			t.Fatalf("clean retirement tombstone quorum state after share %d = %v", index, marked)
		}
	}
}

func TestRetirementCancellationMarkerRequiresStrictQuorumAndGeneration(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	store.values = make(map[string][]byte)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 5
	retiring := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	retiring.Active = false
	params.SettlementDomains[0] = retiring
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEpochClock(), &EpochClock{
		CurrentEpoch: 1, StartHeight: 1, EndHeight: params.EpochBlocks, ValidatorSetId: 5,
		EpochBlocks: params.EpochBlocks,
	})
	generation := bytes.Repeat([]byte{0xe1}, 32)
	store.put(t, KeyForSettlementDomainDeactivation(retiring.Id), &ReplayMarker{Id: generation})
	store.put(t, KeyForSettlementDomainDeactivationEpoch(retiring.Id), &ReplayMarker{Id: uint64Bytes(1)})
	intentID := storeLifecycleIntent(t, store, retiring.Id, generation, "cancel", 1, 10)

	suite := drandbls.NewBLS12381Suite()
	scheme := bdn.NewSchemeOnG2(suite)
	type signer struct {
		address []byte
		private kyber.Scalar
	}
	signers := make([]signer, 2)
	for index := range signers {
		private := suite.G1().Scalar().SetInt64(int64(index + 1))
		public := suite.G1().Point().Mul(private, nil)
		encoded, err := public.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(encoded)
		address := append([]byte(nil), hash[:20]...)
		store.put(t, KeyForEpochValidator(1, address), &Validator{
			Address: address, PublicKey: encoded, StakedAmount: 100, Committees: []uint64{1},
		})
		signers[index] = signer{address: address, private: private}
	}
	blockHash := bytes.Repeat([]byte{0xe2}, 32)
	digest := hashFields(
		[]byte("takusen:settlement-domain-retirement-cancelled"), retiring.Id, uint64Bytes(5),
		uint64Bytes(7), generation, intentID, uint64Bytes(101), blockHash,
	)
	message := &MessageSubmitQuorumSignature{
		ProofKind: "settlement-domain-retirement-cancelled", Digest: digest, Message: digest, ValidatorSetId: 5,
		SettlementDomainId: retiring.Id, RotationNonce: 7, HandoffGeneration: generation, LifecycleIntentId: intentID,
		ControlBlockNumber: 101, ControlBlockHash: blockHash,
	}
	message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, digest)
	for index, signer := range signers {
		message.ObserverAddress = signer.address
		message.Signature, _ = scheme.Sign(signer.private, digest)
		if response := contract.deliverSubmitQuorumSignature(uint64(40+index), message); response.Error != nil {
			t.Fatal(response.Error)
		}
		_, marked := store.values[string(KeyForSettlementDomainRetirementCancellation(retiring.Id, generation))]
		if marked != (index == len(signers)-1) {
			t.Fatalf("retirement cancellation quorum state after share %d = %v", index, marked)
		}
	}
}

func TestRotationCancellationAuthorizationRetainsRecoveryIndex(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	store.values = make(map[string][]byte)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 7
	secondDomain := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	secondDomain.Id = bytes.Repeat([]byte{0x88}, 32)
	secondDomain.ChainId = 56
	params.SettlementDomains = append(params.SettlementDomains, secondDomain)
	store.put(t, KeyForProtocolParams(), params)
	clock := &EpochClock{
		CurrentEpoch: 1, StartHeight: 1, EndHeight: 100, ValidatorSetId: 7,
		EpochBlocks:               params.EpochBlocks,
		ValidatorHandoffTimestamp: 100, ConsensusTimeSeconds: 99,
	}
	completePreparedClock(clock, params, nil)
	store.put(t, KeyForEpochClock(), clock)

	suite := drandbls.NewBLS12381Suite()
	scheme := bdn.NewSchemeOnG2(suite)
	type signer struct {
		address []byte
		private kyber.Scalar
	}
	signers := make([]signer, 2)
	nextValidators := make([]*Validator, 0, len(signers))
	for index := range signers {
		private := suite.G1().Scalar().SetInt64(int64(index + 1))
		public := suite.G1().Point().Mul(private, nil)
		encoded, err := public.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(encoded)
		address := append([]byte(nil), hash[:20]...)
		validator := &Validator{Address: address, PublicKey: encoded, StakedAmount: 100, Committees: []uint64{1}}
		store.put(t, KeyForEpochValidator(1, address), validator)
		store.put(t, KeyForEpochValidator(2, address), validator)
		nextValidators = append(nextValidators, validator)
		signers[index] = signer{address: address, private: private}
	}
	clock.ValidatorHandoffRosterHash = validatorRosterHash(nextValidators)
	store.put(t, KeyForEpochClock(), clock)

	rotationNonce := uint64(4)
	rotationProofID := sha256.Sum256([]byte("queued rotation generation"))
	store.put(t, KeyForQuorumProof(rotationProofID[:]), &QuorumProof{
		ProofKind: "validator-set-rotation", ProofId: rotationProofID[:], ValidatorSetId: 7,
		NewValidatorSetId: 8, RotationNonce: rotationNonce, CompletedHeight: 10,
		SettlementDomainId: params.SettlementDomains[0].Id,
		HandoffGeneration:  validatorHandoffGeneration(clock), HandoffTimestamp: clock.ValidatorHandoffTimestamp,
	})
	indexKey := KeyForRotationProofIndex(params.SettlementDomains[0].Id, 7, 8)
	store.put(t, indexKey, &ReplayMarker{Id: rotationProofID[:]})
	queuedProofID := sha256.Sum256([]byte("finalized queued rotation"))
	store.put(t, KeyForQuorumProof(queuedProofID[:]), &QuorumProof{
		ProofKind: "validator-set-rotation-queued", ProofId: queuedProofID[:], ValidatorSetId: 7,
		NewValidatorSetId: 8, RotationNonce: rotationNonce, CompletedHeight: 11,
		SettlementDomainId: params.SettlementDomains[0].Id,
		HandoffGeneration:  validatorHandoffGeneration(clock), HandoffTimestamp: clock.ValidatorHandoffTimestamp,
	})
	queuedIndexKey := KeyForQueuedRotationIndex(params.SettlementDomains[0].Id, 7, 8)
	store.put(t, queuedIndexKey, &ReplayMarker{Id: queuedProofID[:]})

	digest := sha256.Sum256([]byte("cancel queued rotation generation"))
	message := &MessageSubmitQuorumSignature{
		ProofKind: "validator-set-rotation-cancellation", Digest: digest[:], Message: digest[:],
		ValidatorSetId: 7, NewValidatorSetId: 8, RotationNonce: rotationNonce,
		SettlementDomainId: params.SettlementDomains[0].Id,
		HandoffGeneration:  validatorHandoffGeneration(clock), HandoffTimestamp: clock.ValidatorHandoffTimestamp,
	}
	message.ProofId = quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
	if response := contract.deliverSubmitQuorumSignature(20, message); response.Error == nil {
		t.Fatal("legacy coordinator-driven cancellation share was accepted")
	} else {
		return
	}
	for index, signer := range signers {
		message.ObserverAddress = signer.address
		signature, err := scheme.Sign(signer.private, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		message.Signature = signature
		if response := contract.deliverSubmitQuorumSignature(uint64(20+index), message); response.Error != nil {
			t.Fatal(response.Error)
		}
		_, indexed := store.values[string(indexKey)]
		if index == 0 && !indexed {
			t.Fatal("minority cancellation removed the rotation recovery index")
		}
		if index == 1 && !indexed {
			t.Fatal("cancellation authorization removed recovery state before finalized EVM cancellation")
		}
	}
	if found, err := contract.read(KeyForRotationCancellationIndex(params.SettlementDomains[0].Id, 7, 8), new(ReplayMarker)); err != nil || !found {
		t.Fatalf("cancellation authorization index missing: found=%v err=%v", found, err)
	}
	proof := new(QuorumProof)
	if found, err := contract.read(KeyForQuorumProof(message.ProofId), proof); err != nil || !found ||
		proof.ProofKind != message.ProofKind || proof.RotationNonce != rotationNonce {
		t.Fatalf("completed cancellation proof missing: found=%v err=%v proof=%#v", found, err, proof)
	}

	finalizedDigest := hashFields([]byte("finalized cancellation"))
	finalized := &MessageSubmitQuorumSignature{
		ProofKind: "validator-set-rotation-cancelled", Digest: finalizedDigest, Message: finalizedDigest,
		ValidatorSetId: 7, NewValidatorSetId: 8, RotationNonce: rotationNonce,
		SettlementDomainId: params.SettlementDomains[0].Id,
		HandoffGeneration:  validatorHandoffGeneration(clock), HandoffTimestamp: clock.ValidatorHandoffTimestamp,
	}
	finalized.ProofId = quorumProofID(finalized.ProofKind, finalized.ValidatorSetId, finalized.Digest)
	for index, signer := range signers {
		finalized.ObserverAddress = signer.address
		signature, err := scheme.Sign(signer.private, finalizedDigest)
		if err != nil {
			t.Fatal(err)
		}
		finalized.Signature = signature
		if response := contract.deliverSubmitQuorumSignature(uint64(30+index), finalized); response.Error != nil {
			t.Fatal(response.Error)
		}
	}
	if _, found := store.values[string(indexKey)]; !found {
		t.Fatal("finalized cancellation removed the immutable rotation recovery index before attempt reset")
	}
	for _, key := range [][]byte{queuedIndexKey, KeyForRotationCancellationIndex(params.SettlementDomains[0].Id, 7, 8)} {
		if _, found := store.values[string(key)]; found {
			t.Fatalf("finalized cancellation retained handoff index %x", key)
		}
	}
	if found, err := contract.read(KeyForRotationResolutionIndex(params.SettlementDomains[0].Id, 7, 8), new(ReplayMarker)); err != nil || !found {
		t.Fatalf("finalized cancellation resolution missing: found=%v err=%v", found, err)
	}
}

func TestActiveValidatorsUsesImmutableEpochSnapshotAfterBondChange(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	store.values = make(map[string][]byte)
	params := defaultProtocolParams()
	params.Revision, params.MinimumValidatorBond = 1, 100
	store.put(t, KeyForProtocolParams(), params)

	below := &Validator{Address: bytes.Repeat([]byte{1}, 20), StakedAmount: 99, Committees: []uint64{1}}
	eligible := &Validator{Address: bytes.Repeat([]byte{2}, 20), StakedAmount: 100, Committees: []uint64{1}}
	store.put(t, KeyForEpochValidator(1, below.Address), below)
	store.put(t, KeyForEpochValidator(1, eligible.Address), eligible)

	validators, total, err := contract.activeValidators()
	if err != nil {
		t.Fatal(err)
	}
	if len(validators) != 2 || validators[hex.EncodeToString(below.Address)] == nil ||
		validators[hex.EncodeToString(eligible.Address)] == nil || total != 199 {
		t.Fatalf("frozen epoch snapshot was repriced: validators=%d total=%d", len(validators), total)
	}
}

func TestPreparedRotationRequiresExactRawVotingPower(t *testing.T) {
	for _, weights := range [][]uint64{{1, 1, 1}, {1, 2, 6}} {
		t.Run(fmt.Sprint(weights), func(t *testing.T) {
			contract, store, _, _ := newMemoryContract(t)
			store.values = make(map[string][]byte)
			params := defaultProtocolParams()
			params.Revision, params.ValidatorSetId = 1, 5
			store.put(t, KeyForProtocolParams(), params)
			suite := drandbls.NewBLS12381Suite()
			validators := make([]*Validator, len(weights))
			for index, weight := range weights {
				private := suite.G1().Scalar().SetInt64(int64(index + 1))
				public := suite.G1().Point().Mul(private, nil)
				encoded, err := public.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				digest := sha256.Sum256(encoded)
				validator := &Validator{Address: append([]byte(nil), digest[:20]...), PublicKey: encoded, StakedAmount: weight, Committees: []uint64{1}}
				validators[index] = validator
				store.put(t, KeyForEpochValidator(2, validator.Address), validator)
			}
			sort.Slice(validators, func(i, j int) bool { return bytes.Compare(validators[i].PublicKey, validators[j].PublicKey) < 0 })
			rawWeights := make([]uint64, len(validators))
			for index, validator := range validators {
				rawWeights[index] = validator.StakedAmount
			}
			_, rawHash, _, manifestErr := contract.evmRosterHashes(2, nil)
			if manifestErr != nil || !bytes.Equal(rawHash, keccak256(abiEncodeUint96Array(rawWeights))) {
				t.Fatalf("raw weights rejected: hash=%x err=%v", rawHash, manifestErr)
			}
			var total, assigned uint64
			normalized := make([]uint64, len(validators))
			for _, validator := range validators {
				total += validator.StakedAmount
			}
			for index, validator := range validators {
				normalized[index] = validator.StakedAmount * 1_000_000 / total
				if index == len(validators)-1 {
					normalized[index] = 1_000_000 - assigned
				}
				assigned += normalized[index]
			}
			if bytes.Equal(rawHash, keccak256(abiEncodeUint96Array(normalized))) {
				t.Fatal("normalized validator weights were accepted")
			}
		})
	}
}
