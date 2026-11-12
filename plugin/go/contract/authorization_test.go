package contract

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestDirectEOAAuthorizationMatchesEIP712(t *testing.T) {
	private := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	public := private.PubKey().SerializeUncompressed()
	requester := keccak(public[1:])[12:]
	domainConfig := defaultSettlementDomain()
	domainConfig.ChainId = 31337
	domainConfig.EscrowAddress = bytes.Repeat([]byte{9}, 20)
	domainConfig.Id = keccak(abiUint64(domainConfig.ChainId), abiAddress(domainConfig.TokenAddress), abiAddress(domainConfig.EscrowAddress), abiAddress(domainConfig.VerifierAddress))
	params := &ProtocolParams{SettlementDomains: []*SettlementDomain{domainConfig}}
	message := &MessageObserveAuthorization{SettlementDomainId: domainConfig.Id,
		RequestId: "request", InputHash: bytes.Repeat([]byte{3}, 32), Requester: requester,
		ReservedBudget: 300_000, AuthorizationDeadline: 1_800_000_000,
	}
	domain := keccak(
		keccak([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
		keccak([]byte("Takusen Escrow")), keccak([]byte("1")), abiUint64(domainConfig.ChainId), abiAddress(domainConfig.EscrowAddress),
	)
	requestID := sha256.Sum256([]byte(message.RequestId))
	structure := keccak(
		keccak([]byte("AuthorizeRequest(bytes32 requestId,bytes32 inputHash,bytes32 settlementDomain,address requester,uint128 budget,uint64 deadline)")),
		requestID[:], message.InputHash, message.SettlementDomainId, abiAddress(message.Requester), abiUint64(message.ReservedBudget), abiUint64(message.AuthorizationDeadline),
	)
	compact := secpECDSA.SignCompact(private, keccak([]byte{0x19, 0x01}, domain, structure), false)
	message.AuthorizationSignature = append(append([]byte(nil), compact[1:]...), compact[0]-27)
	if err := verifyEOARequestAuthorization(message, params); err != nil {
		t.Fatal(err)
	}
	message.AuthorizationDeadline = 0
	if err := verifyEOARequestAuthorization(message, params); err == nil {
		t.Fatal("accepted a zero authorization deadline")
	}
	message.AuthorizationDeadline = 1_800_000_000
	message.Requester[0] ^= 0xff
	if err := verifyEOARequestAuthorization(message, params); err == nil {
		t.Fatal("accepted an authorization for a different requester")
	}
}

func TestAuthorizationBatchValidation(t *testing.T) {
	observer := bytes.Repeat([]byte{1}, 20)
	authorization := func(requestID string) *MessageObserveAuthorization {
		message := &MessageObserveAuthorization{SettlementDomainId: testSettlementDomainID(),
			ObserverAddress: observer, RequestId: requestID, InputHash: bytes.Repeat([]byte{2}, 32),
			RequestArchiveId: "sha256:0202020202020202020202020202020202020202020202020202020202020202",
			Requester:        bytes.Repeat([]byte{3}, 20), ReservedBudget: 1, OutputType: "boolean",
			OutputMinimum: 0, OutputMaximum: 1,
			Models: []string{"model"}, ExecutionQuorum: 1, DeadlineHeight: 2,
			AuthorizationSignature: []byte{1}, AuthorizationDeadline: 3,
		}
		message.SchemaHash = requestOutputSchemaHash(message)
		return message
	}
	message := &MessageObserveAuthorizations{ObserverAddress: observer, Authorizations: []*MessageObserveAuthorization{authorization("one"), authorization("two")}}
	if signer, err := checkObserveAuthorizations(message); err != nil || !bytes.Equal(signer, observer) {
		t.Fatalf("valid batch rejected: signer=%x err=%v", signer, err)
	}
	message.Authorizations[1].RequestId = "one"
	if _, err := checkObserveAuthorizations(message); err == nil {
		t.Fatal("duplicate request was accepted")
	}
	message.Authorizations[1] = authorization("two")
	message.Authorizations[1].ObserverAddress = bytes.Repeat([]byte{4}, 20)
	if _, err := checkObserveAuthorizations(message); err == nil {
		t.Fatal("mismatched observer was accepted")
	}
}

func TestVerifyEOARequestAuthorizationsPreservesInputOrder(t *testing.T) {
	params := defaultProtocolParams()
	first := &MessageObserveAuthorization{SettlementDomainId: testSettlementDomainID(),
		Requester: bytes.Repeat([]byte{1}, 20), AuthorizationDeadline: 360,
		AuthorizationSignature: make([]byte, 65),
	}
	first.AuthorizationSignature[64] = 9
	second := &MessageObserveAuthorization{SettlementDomainId: testSettlementDomainID(), Requester: bytes.Repeat([]byte{2}, 20), AuthorizationDeadline: 360}
	err := verifyEOARequestAuthorizations([]*MessageObserveAuthorization{first, second}, params)
	if err == nil || err.Msg != "invalid EOA recovery identifier" {
		t.Fatalf("first input error = %#v", err)
	}
}

func TestAuthorizationWindowExpiresAtCanopyHeight(t *testing.T) {
	if !authorizationWindowValid(100, 460, 360) {
		t.Fatal("governed live authorization window was rejected")
	}
	if authorizationWindowValid(100, 100, 360) || authorizationWindowValid(100, 99, 360) || authorizationWindowValid(100, 461, 360) {
		t.Fatal("expired or overlong authorization window was accepted")
	}
}
