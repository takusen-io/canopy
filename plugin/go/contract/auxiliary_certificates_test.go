package contract

import (
	"bytes"
	"encoding/json"
	"testing"

	drandbls "github.com/drand/kyber-bls12381"
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

func TestAuxiliaryCertificatePersistsStrictQuorumWithoutAffectingConsensus(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.ValidatorSetId = 7
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEpochClock(), &EpochClock{CurrentEpoch: 1, ValidatorSetId: 7, StartHeight: 1, EndHeight: 100})

	digest := bytes.Repeat([]byte{0x42}, 32)
	suite := drandbls.NewBLS12381Suite()
	signature, err := bdn.NewSchemeOnG2(suite).Sign(suite.G1().Scalar().SetInt64(1), digest)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &AuxiliaryCandidate{Kind: "test-native", Key: uint64Bytes(9), Digest: digest, Payload: []byte("bounded")}
	certificates := []*AuxiliaryCertificate{{
		Candidate: candidate,
		Signature: &AuxiliaryAggregateSignature{Signature: signature, Bitmap: []byte{0x03}},
	}}
	records := contract.consumeAuxiliaryCertificates(12, certificates)
	record, ok := records[string(KeyForConsensusCertificate(candidate.Kind, candidate.Key, candidate.Digest))].(*ConsensusCertificate)
	if !ok || record.ValidatorSetId != 7 || record.ValidatorEpoch != 1 || record.SignedWeight != 200 ||
		record.TotalWeight != 200 || record.CompletedHeight != 12 || len(record.AggregateSignatureEip2537) != 256 {
		t.Fatalf("unexpected persisted certificate: %+v", record)
	}

	certificates[0].Signature.Bitmap = []byte{0x01}
	if got := contract.consumeAuxiliaryCertificates(13, certificates); len(got) != 0 {
		t.Fatal("certificate without strict two-thirds weight was persisted")
	}
}
