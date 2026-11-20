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

	// Reproduce core's stake-descending/address-descending committee order so
	// the bitmap and BDN coefficients have one canonical meaning end to end.
	validators, _, stateErr := contract.activeValidators()
	if stateErr != nil {
		t.Fatal(stateErr)
	}
	ordered := make([]*Validator, 0, len(validators))
	for _, validator := range validators {
		ordered = append(ordered, validator)
	}
	sortValidatorsByConsensusOrder(ordered)
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
	signerIndexes := []int{0, 2, 3}
	partials := make([][]byte, 0, 3)
	for _, i := range signerIndexes {
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
	publicKeyOrdered := append([]*Validator(nil), ordered...)
	sort.Slice(publicKeyOrdered, func(i, j int) bool {
		return bytes.Compare(publicKeyOrdered[i].PublicKey, publicKeyOrdered[j].PublicKey) < 0
	})
	if string(publicKeyOrdered[0].PublicKey)+string(publicKeyOrdered[2].PublicKey)+string(publicKeyOrdered[3].PublicKey) ==
		string(ordered[0].PublicKey)+string(ordered[2].PublicKey)+string(ordered[3].PublicKey) {
		t.Fatal("test fixture does not distinguish consensus and public-key bitmap order")
	}
	wrongPoints := make([]kyber.Point, len(publicKeyOrdered))
	for i, validator := range publicKeyOrdered {
		wrongPoints[i], err = bdnPublicKey(validator.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
	}
	wrongMask, err := sign.NewMask(suite, wrongPoints, nil)
	if err != nil {
		t.Fatal(err)
	}
	wrongPartials := make([][]byte, 0, 3)
	for _, i := range signerIndexes {
		if err = wrongMask.SetBit(i, true); err != nil {
			t.Fatal(err)
		}
		partial, signErr := scheme.Sign(privateByPublic[string(publicKeyOrdered[i].PublicKey)], digest[:])
		if signErr != nil {
			t.Fatal(signErr)
		}
		wrongPartials = append(wrongPartials, partial)
	}
	wrongAggregate, err := scheme.AggregateSignatures(wrongPartials, wrongMask)
	if err != nil {
		t.Fatal(err)
	}
	wrongSignature, err := wrongAggregate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if certErr := contract.verifyValidatorCertificate(digest[:], 5, wrongMask.Mask(), wrongSignature); certErr == nil {
		t.Fatal("public-key-ordered partial quorum was reinterpreted as a consensus bitmap")
	}
	mask.SetBit(3, false)
	if certErr := contract.verifyValidatorCertificate(digest[:], 5, mask.Mask(), encodedAggregate); certErr == nil {
		t.Fatal("accepted a certificate without strict two-thirds stake")
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
			sortValidatorsByConsensusOrder(validators)
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
