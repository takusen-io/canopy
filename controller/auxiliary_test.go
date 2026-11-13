package controller

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/canopy-network/canopy/fsm"
	"github.com/canopy-network/canopy/lib"
	"github.com/canopy-network/canopy/lib/crypto"
	"github.com/canopy-network/canopy/store"
	"google.golang.org/protobuf/proto"
)

type fixedValidatorSetRCManager struct {
	lib.RCManagerI
	validatorSet lib.ValidatorSet
}

func (m fixedValidatorSetRCManager) GetValidatorSet(_, _, _ uint64) (lib.ValidatorSet, lib.ErrorI) {
	return m.validatorSet, nil
}

func TestAuxiliaryCandidateOutboxSurvivesRestart(t *testing.T) {
	config := lib.DefaultConfig()
	config.DataDirPath = t.TempDir()
	first := &Controller{Config: config, auxiliaryCandidates: make(map[string]*lib.AuxiliaryCandidate)}
	candidate := &lib.AuxiliaryCandidate{
		Kind: "evm-observation/deposit", Key: []byte("deposit-key"),
		Digest: bytes.Repeat([]byte{1}, 32), Payload: []byte("finalized evidence"),
	}
	if err := first.SubmitAuxiliaryCandidate(candidate); err != nil {
		t.Fatal(err)
	}
	restarted := &Controller{Config: config, auxiliaryCandidates: make(map[string]*lib.AuxiliaryCandidate)}
	if err := restarted.loadAuxiliaryCandidates(); err != nil {
		t.Fatal(err)
	}
	loaded := restarted.auxiliaryCandidates[candidate.Kind+string(candidate.Key)]
	if loaded == nil || !bytes.Equal(loaded.Digest, candidate.Digest) || !bytes.Equal(loaded.Payload, candidate.Payload) {
		t.Fatalf("durable candidate was lost: %+v", loaded)
	}
}

func TestAuxiliaryCandidateCheckpointCanAdvanceBeforeCertification(t *testing.T) {
	config := lib.DefaultConfig()
	config.DataDirPath = t.TempDir()
	controller := &Controller{Config: config, auxiliaryCandidates: make(map[string]*lib.AuxiliaryCandidate)}
	key := []byte("authority")
	for value := byte(1); value <= 2; value++ {
		if err := controller.SubmitAuxiliaryCandidate(&lib.AuxiliaryCandidate{
			Kind: "evm-observation/settlement-domain-authority", Key: key,
			Digest: bytes.Repeat([]byte{value}, 32), Payload: []byte{value},
		}); err != nil {
			t.Fatal(err)
		}
	}
	loaded := controller.auxiliaryCandidates["evm-observation/settlement-domain-authority"+string(key)]
	if loaded == nil || loaded.Digest[0] != 2 {
		t.Fatalf("stale checkpoint pinned candidate pool: %+v", loaded)
	}
}

func TestAuxiliaryCandidateOutboxAcceptsBurstBeyondBlockCapacity(t *testing.T) {
	config := lib.DefaultConfig()
	config.DataDirPath = t.TempDir()
	controller := &Controller{Config: config, auxiliaryCandidates: make(map[string]*lib.AuxiliaryCandidate)}
	for index := 0; index < 64; index++ {
		if err := controller.SubmitAuxiliaryCandidate(&lib.AuxiliaryCandidate{
			Kind: "evm-observation/deposit", Key: []byte(fmt.Sprintf("deposit-%03d", index)),
			Digest: bytes.Repeat([]byte{byte(index + 1)}, 32), Payload: []byte{byte(index)},
		}); err != nil {
			t.Fatalf("candidate %d: %v", index, err)
		}
	}
	if len(controller.auxiliaryCandidates) != 64 {
		t.Fatalf("outbox size = %d, want 64", len(controller.auxiliaryCandidates))
	}
}

func TestOlderAuxiliaryCertificateDoesNotConsumeReplacement(t *testing.T) {
	config := lib.DefaultConfig()
	config.DataDirPath = t.TempDir()
	controller := &Controller{Config: config, auxiliaryCandidates: make(map[string]*lib.AuxiliaryCandidate), log: lib.NewNullLogger()}
	key := []byte("authority")
	older := &lib.AuxiliaryCandidate{
		Kind: "evm-observation/settlement-domain-authority", Key: key,
		Digest: bytes.Repeat([]byte{1}, 32), Payload: []byte("older"),
	}
	newer := &lib.AuxiliaryCandidate{
		Kind: older.Kind, Key: key,
		Digest: bytes.Repeat([]byte{2}, 32), Payload: []byte("newer"),
	}
	if err := controller.SubmitAuxiliaryCandidate(older); err != nil {
		t.Fatal(err)
	}
	if err := controller.SubmitAuxiliaryCandidate(newer); err != nil {
		t.Fatal(err)
	}

	controller.consumeAuxiliaryCertificates([]*lib.AuxiliaryCertificate{{Candidate: older}})
	logical := newer.Kind + string(newer.Key)
	if stored := controller.auxiliaryCandidates[logical]; stored == nil || !bytes.Equal(stored.Digest, newer.Digest) {
		t.Fatalf("newer candidate was consumed by older certificate: %+v", stored)
	}

	controller.consumeAuxiliaryCertificates([]*lib.AuxiliaryCertificate{{Candidate: newer}})
	if stored := controller.auxiliaryCandidates[logical]; stored != nil {
		t.Fatalf("exact certified candidate was not consumed: %+v", stored)
	}
}

func TestMaliciousProposalRejectsPayloadSubstitutedAuxiliaryCertificate(t *testing.T) {
	keys := make([]crypto.PrivateKeyI, 3)
	validators := &lib.ConsensusValidators{}
	for index := range keys {
		key, err := crypto.NewBLS12381PrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys[index] = key
		validators.ValidatorSet = append(validators.ValidatorSet, &lib.ConsensusValidator{PublicKey: key.PublicKey().Bytes(), VotingPower: 1})
	}
	validatorSet, err := lib.NewValidatorSet(validators)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &lib.AuxiliaryCandidate{
		Kind: "evm-observation/deposit", Key: []byte("deposit"),
		Digest: bytes.Repeat([]byte{7}, 32), Payload: []byte("verified payload"),
	}
	qc := &lib.QuorumCertificate{Header: &lib.View{Height: 1, RootHeight: 1}, BlockHash: bytes.Repeat([]byte{8}, 32)}
	ordinaryMulti, auxiliaryMulti := validatorSet.MultiKey.Copy(), validatorSet.MultiKey.Copy()
	for index, key := range keys {
		if signErr := ordinaryMulti.AddSigner(key.Sign(qc.SignBytes()), index); signErr != nil {
			t.Fatal(signErr)
		}
		if signErr := auxiliaryMulti.AddSigner(key.Sign(lib.AuxiliaryCandidateSignBytes(candidate)), index); signErr != nil {
			t.Fatal(signErr)
		}
	}
	ordinarySignature, aggregateErr := ordinaryMulti.AggregateSignatures()
	if aggregateErr != nil {
		t.Fatal(aggregateErr)
	}
	qc.Signature = &lib.AggregateSignature{Signature: ordinarySignature, Bitmap: []byte{0x07}}
	auxiliarySignature, aggregateErr := auxiliaryMulti.AggregateSignatures()
	if aggregateErr != nil {
		t.Fatal(aggregateErr)
	}
	qc.AuxiliaryCertificates = []*lib.AuxiliaryCertificate{{Candidate: candidate, Signature: &lib.AggregateSignature{Signature: auxiliarySignature, Bitmap: []byte{0x07}}}}
	indexedQC := proto.Clone(qc).(*lib.QuorumCertificate)
	// A malicious proposer can leave the ordinary QC aggregate valid because
	// auxiliary envelopes are deliberately outside ordinary block sign bytes.
	qc.AuxiliaryCertificates[0].Candidate.Payload = []byte("forged payload")
	if partial, checkErr := qc.Signature.Check(qc, validatorSet); checkErr != nil || partial {
		t.Fatalf("ordinary QC unexpectedly became invalid: partial=%v err=%v", partial, checkErr)
	}
	controller := &Controller{}
	if checkErr := controller.validateAuxiliaryCertificates(qc, validatorSet); checkErr == nil {
		t.Fatal("controller accepted a forged auxiliary envelope before application BeginBlock")
	}

	config := lib.DefaultConfig()
	config.ChainId = 2 // force historical committee resolution through the root-chain manager stub
	database, err := store.NewStoreInMemory(lib.NewNullLogger())
	if err != nil {
		t.Fatal(err)
	}
	state := &fsm.StateMachine{Config: config}
	state.SetStore(database)
	if err := state.SetParamsCons(fsm.DefaultParams().Consensus); err != nil {
		t.Fatal(err)
	}
	if err := database.IndexQC(indexedQC); err != nil {
		t.Fatal(err)
	}
	if err := database.IndexBlock(&lib.BlockResult{BlockHeader: &lib.BlockHeader{Height: 1}}); err != nil {
		t.Fatal(err)
	}
	controller = &Controller{
		Config: config, FSM: state,
		RCManager: fixedValidatorSetRCManager{validatorSet: validatorSet}, log: lib.NewNullLogger(),
	}
	checkErr := controller.CheckAndSetLastCertificate(&lib.BlockHeader{Height: 2, LastQuorumCertificate: qc})
	if checkErr == nil {
		t.Fatal("malicious proposer path accepted forged auxiliary certificate")
	}
	if checkErr.Error() == lib.ErrInvalidLastQuorumCertificate().Error() {
		t.Fatalf("malicious proposer test did not reach auxiliary aggregate validation: %v", checkErr)
	}
}
