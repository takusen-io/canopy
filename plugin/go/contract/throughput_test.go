package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestExecutionCohortPrefetchIncludesReservationsInOneStateRead(t *testing.T) {
	contract, store, servicer, _ := newMemoryContract(t)
	domain := testSettlementDomainID()
	authenticated := []authenticatedExecution{{parsed: &receipt{
		ExecutionID: "execution", RequestID: "request", SettlementDomain: "0x" + hex.EncodeToString(domain), TEEKeyID: "ed25519:key",
	}}}

	before := store.stateReadCalls
	loaded, err := contract.prefetchExecutionState(servicer, authenticated)
	if err != nil {
		t.Fatal(err)
	}
	if calls := store.stateReadCalls - before; calls != 1 {
		t.Fatalf("execution cohort used %d state-read round trips, want 1", calls)
	}
	if _, ok := loaded[string(KeyForReservation(domain, "request"))]; !ok {
		t.Fatal("reservation was not included in the execution cohort prefetch")
	}
}

func TestSettlementCandidatesBatchStateReads(t *testing.T) {
	contract, store, servicerAddress, _ := newMemoryContract(t)
	domain := testSettlementDomainID()
	requester := bytes.Repeat([]byte{4}, 20)
	store.put(t, KeyForServicer(servicerAddress), &Servicer{
		OwnerAddress:     servicerAddress,
		EvmPayoutAddress: bytes.Repeat([]byte{5}, 20),
	})
	for _, suffix := range []string{"a", "b"} {
		requestID := "request-" + suffix
		requestHash := sha256.Sum256([]byte(requestID))
		modelHash := sha256.Sum256([]byte("model"))
		executionID := settlementExecutionID(domain, requestHash, modelHash, servicerAddress, bytes.Repeat([]byte{6}, 32))
		store.put(t, KeyForRequest(requestID), &RequestRecord{
			SettlementDomainId: domain, RequestId: requestID, InputHash: bytes.Repeat([]byte{6}, 32),
			Requester: requester, Models: []string{"model"}, OutputType: "boolean", Status: "ready",
			Assignments: []*Assignment{{Model: "model", Completed: true, ExecutionId: executionID}},
		})
		store.put(t, KeyForReservation(domain, requestID), &ReservationRecord{
			SettlementDomainId: domain, RequestId: requestID, Requester: requester, Budget: 100, Spent: 10, Status: "reserved",
		})
		store.put(t, KeyForExecution(executionID), &ExecutionRecord{
			SettlementDomainId: domain, ExecutionId: executionID, RequestId: requestID, Model: "model",
			ServicerAddress: servicerAddress, Status: "success", Output: "true", Cost: 10, ProviderCost: 10,
		})
		store.put(t, KeyForSettlementIndex(requestID), &RequestRecord{RequestId: requestID})
		store.put(t, KeyForUncertifiedSettlementIndex(requestID), &RequestRecord{RequestId: requestID})
	}

	before := store.stateReadCalls
	candidates, err := contract.settlementAuxiliaryCandidates(&EpochClock{ValidatorSetId: 1}, 64)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 {
		t.Fatalf("settlement candidates = %d, want one batched candidate", len(candidates))
	}
	batch := new(certifiedSettlementBatch)
	if json.Unmarshal(candidates[0].Payload, batch) != nil || len(batch.Requests) != 2 {
		t.Fatalf("invalid settlement payload: %s", candidates[0].Payload)
	}
	for _, request := range batch.Requests {
		if !request.FinalizesRequest {
			t.Fatalf("ready request %s did not carry terminal settlement metadata", request.RequestID)
		}
	}
	if calls := store.stateReadCalls - before; calls != 6 {
		t.Fatalf("settlement discovery used %d state-read round trips, want 6", calls)
	}

	store.put(t, KeyForCertifiedSettlementIndex("request-a"), &ReplayMarker{Id: uint64Bytes(7)})
	candidates, err = contract.settlementAuxiliaryCandidates(&EpochClock{ValidatorSetId: 1}, 64)
	if err != nil || len(candidates) != 1 {
		t.Fatalf("serialized settlement candidates = %d, err = %v", len(candidates), err)
	}
	batch = new(certifiedSettlementBatch)
	if json.Unmarshal(candidates[0].Payload, batch) != nil || len(batch.Requests) != 1 || batch.Requests[0].RequestID != "request-b" {
		t.Fatalf("in-flight certificate did not serialize its request: %s", candidates[0].Payload)
	}
}
