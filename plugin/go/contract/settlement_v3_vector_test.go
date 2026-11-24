package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestProtocolV6SettlementDigestMatchesEVMVector(t *testing.T) {
	domain := mustHex("0xe61c642ed6163bf7964492c21077aae61e1427acd195e16e0a705c65a2943889", 32)
	requestID := sha256.Sum256([]byte("request-1"))
	modelID := sha256.Sum256([]byte("model-1"))
	servicer := mustHex("0x63b12fbf2BAEc17A925922a8bC0d90406C3d28C8", 20)
	executionID := settlementExecutionID(domain, requestID, modelID, servicer, mustHex("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 32))
	requests := []certifiedSettlementRequest{{
		SettlementDomain: "0xe61c642ed6163bf7964492c21077aae61e1427acd195e16e0a705c65a2943889",
		RequestID:        "request-1",
		InputHash:        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Models:           []string{"model-1"}, OutputType: "boolean",
		OutputSchema: certifiedSettlementSchema{Minimum: 0, Maximum: 1}, Deadline: 100,
		Requester: "0x5e23eCFF53FC9d493Fd07CeC190106e44c4A536a", ReservedBudget: 10, RequestSpent: 1,
		Initialize: true,
		Executions: []certifiedSettlementExecution{{
			ExecutionID: executionID, Model: "model-1", ServicerOwner: "0x63b12fbf2BAEc17A925922a8bC0d90406C3d28C8", Servicer: "0x63b12fbf2BAEc17A925922a8bC0d90406C3d28C8",
			Output: "true", OutputType: "boolean", Status: "success", CostMicros: 1, ServicerPaymentMicros: 1,
		}},
	}}
	digest, err := settlementAuthorizationDigest(1, 9, requests)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(digest); got != "1adab07f8f91cf5a5b9f1257a1eb3828532f16bb35328dd14f88fc3d8ff147f3" {
		t.Fatalf("v6 settlement digest = %s", got)
	}
}
