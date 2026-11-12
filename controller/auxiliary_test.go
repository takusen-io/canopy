package controller

import (
	"bytes"
	"testing"

	"github.com/canopy-network/canopy/lib"
)

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
