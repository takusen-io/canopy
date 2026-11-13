package contract

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/drand/kyber"
	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bdn"
	"google.golang.org/protobuf/proto"
)

func TestCertifiedEVMDepositAppliesWithoutObservationTransactions(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.ValidatorSetId = 7
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEpochClock(), &EpochClock{CurrentEpoch: 1, ValidatorSetId: 7, StartHeight: 1, EndHeight: 100})
	domain := params.SettlementDomains[0]
	message := &MessageObserveDeposit{
		SettlementDomainId: domain.Id, ChainTxHash: bytes.Repeat([]byte{0x31}, 32),
		Requester: bytes.Repeat([]byte{0x41}, 20), AmountMicros: 25, TokenAmount: []byte{25},
	}
	encoded, err := Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	observation := &certifiedEVMObservation{
		Kind: "deposit", SettlementDomainID: domain.Id, BlockNumber: 9,
		BlockHash: bytes.Repeat([]byte{0x51}, 32), Message: encoded,
	}
	payload, jsonErr := json.Marshal(observation)
	if jsonErr != nil {
		t.Fatal(jsonErr)
	}
	claim := message.ChainTxHash
	candidate := &AuxiliaryCandidate{
		Kind: "evm-observation/deposit", Key: hashFields([]byte("deposit"), domain.Id, claim),
		Digest: evmObservationDigest(observation, depositSubject(message)), Payload: payload,
	}
	certificate := &ConsensusCertificate{ValidatorSetId: 7, SignedWeight: 200, TotalWeight: 200}
	if !contract.applyNativeAuxiliaryCertificate(12, candidate, certificate, map[string]proto.Message{}) {
		t.Fatal("certified deposit was rejected")
	}
	account := new(CreditAccount)
	if found, readErr := contract.read(KeyForCredit(domain.Id, message.Requester), account); readErr != nil || !found || account.Deposited != 25 {
		t.Fatalf("account=%+v found=%v err=%v", account, found, readErr)
	}

	conflict := proto.Clone(candidate).(*AuxiliaryCandidate)
	conflict.Digest = bytes.Repeat([]byte{0x99}, 32)
	if contract.applyNativeAuxiliaryCertificate(13, conflict, certificate, map[string]proto.Message{}) {
		t.Fatal("conflicting finalized block digest was accepted")
	}
}

func TestAuxiliaryCertificatePersistsCoreValidatedRelayArtifact(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.ValidatorSetId = 7
	store.put(t, KeyForProtocolParams(), params)
	// BeginBlock is already in N+1, but the predecessor QC was signed by N.
	store.put(t, KeyForEpochClock(), &EpochClock{CurrentEpoch: 2, ValidatorSetId: 8, StartHeight: 13, EndHeight: 100})
	var outgoing []*Validator
	for epoch, firstIndex := range map[uint64]byte{1: 1, 2: 3} {
		for index := firstIndex; index < firstIndex+2; index++ {
			address := bytes.Repeat([]byte{index}, addressSize)
			validator := &Validator{
				Address: address, PublicKey: testBDNPublicKey(int64(index)), StakedAmount: 100, Committees: []uint64{1},
			}
			store.put(t, KeyForEpochValidator(epoch, address), validator)
			if epoch == 1 {
				outgoing = append(outgoing, validator)
			}
		}
	}

	digest := bytes.Repeat([]byte{0x42}, 32)
	suite := drandbls.NewBLS12381Suite()
	candidate := &AuxiliaryCandidate{Kind: "test-native", Key: uint64Bytes(9), Digest: digest, Payload: []byte("bounded")}
	sortValidatorsByConsensusOrder(outgoing)
	points := make([]kyber.Point, len(outgoing))
	for index, validator := range outgoing {
		point, pointErr := bdnPublicKey(validator.PublicKey)
		if pointErr != nil {
			t.Fatal(pointErr)
		}
		points[index] = point
	}
	mask, err := sign.NewMask(suite, points, nil)
	if err != nil {
		t.Fatal(err)
	}
	partials := make([][]byte, 0, 2)
	for index, validator := range outgoing {
		scalar := suite.G1().Scalar().SetInt64(1)
		if bytes.Equal(validator.PublicKey, testBDNPublicKey(2)) {
			scalar = suite.G1().Scalar().SetInt64(2)
		}
		// Sign unrelated bytes. Core is the sole authentication boundary, so the
		// plugin must persist this well-formed relay artifact without repeating
		// BDN verification against the candidate envelope.
		partial, signErr := bdn.NewSchemeOnG2(suite).Sign(scalar, []byte("already-verified-by-core"))
		if signErr != nil || mask.SetBit(index, true) != nil {
			t.Fatal(signErr)
		}
		partials = append(partials, partial)
	}
	signature, err := bdn.NewSchemeOnG2(suite).AggregateSignatures(partials, mask)
	if err != nil {
		t.Fatal(err)
	}
	encodedSignature, err := signature.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	certificates := []*AuxiliaryCertificate{{
		Candidate: candidate,
		Signature: &AuxiliaryAggregateSignature{Signature: encodedSignature, Bitmap: mask.Mask()},
	}}
	records := contract.consumeAuxiliaryCertificates(13, certificates)
	record, ok := records[string(KeyForConsensusCertificate(candidate.Kind, candidate.Key, candidate.Digest))].(*ConsensusCertificate)
	if !ok || record.ValidatorSetId != 7 || record.ValidatorEpoch != 1 || record.SignedWeight != 200 ||
		record.TotalWeight != 200 || record.CompletedHeight != 13 || len(record.AggregateSignatureEip2537) != 256 {
		t.Fatalf("unexpected persisted certificate: %+v", record)
	}
}

func TestUnchangedRosterPredecessorCertificateRetainsSignerEpoch(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.ValidatorSetId = 7
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEpochClock(), &EpochClock{CurrentEpoch: 2, ValidatorSetId: 7, StartHeight: 13, EndHeight: 100})
	for epoch := uint64(1); epoch <= 2; epoch++ {
		for index := byte(1); index <= 2; index++ {
			address := bytes.Repeat([]byte{index}, addressSize)
			store.put(t, KeyForEpochValidator(epoch, address), &Validator{
				Address: address, PublicKey: testBDNPublicKey(int64(index)), StakedAmount: 100, Committees: []uint64{1},
			})
		}
	}
	snapshot, err := contract.auxiliaryValidatorSnapshot(13)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.epoch != 1 || snapshot.validatorSetID != 7 {
		t.Fatalf("snapshot epoch=%d set=%d, want epoch=1 set=7", snapshot.epoch, snapshot.validatorSetID)
	}
}
