package contract

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

func TestQueueAuthorizationPublishesIntentWithoutValidatorApproval(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.AuthorizationDeadlineBlocks = 360
	store.put(t, KeyForProtocolParams(), params)
	relayer := bytes.Repeat([]byte{0x91}, 20)
	authorization := &Authorization{
		SettlementDomainId: params.SettlementDomains[0].Id, RequestId: "erc1271-request",
		InputHash: bytes.Repeat([]byte{2}, 32), RequestArchiveId: "sha256:" + strings.Repeat("02", 32),
		Requester: bytes.Repeat([]byte{3}, 20), ReservedBudget: 10, OutputType: "boolean",
		OutputMinimum: 0, OutputMaximum: 1, Models: testModelBudgets(10, "model"), ExecutionQuorum: 1,
		DeadlineHeight: 200, AuthorizationSignature: []byte{1, 2, 3}, AuthorizationDeadline: 200,
		AuthorizationChainBlockNumber: 77, AuthorizationChainBlockHash: bytes.Repeat([]byte{4}, 32),
	}
	authorization.SchemaHash = requestOutputSchemaHash(authorization)
	message := &MessageQueueAuthorization{RelayerAddress: relayer, Authorization: authorization}
	if signer, err := checkQueueAuthorization(message); err != nil || !bytes.Equal(signer, relayer) {
		t.Fatalf("queued authorization validation: signer=%x err=%v", signer, err)
	}
	if response := contract.deliverQueueAuthorization(100, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	pending := new(PendingAuthorization)
	if found, err := contract.read(KeyForPendingAuthorization(authorization.RequestId), pending); err != nil || !found {
		t.Fatalf("pending authorization missing: found=%v err=%v", found, err)
	}
	decoded := new(Authorization)
	if proto.Unmarshal(pending.Authorization, decoded) != nil || decoded.RequestId != authorization.RequestId {
		t.Fatalf("pending authorization = %+v", decoded)
	}
}

func TestDirectEOAAuthorizationMatchesEIP712(t *testing.T) {
	private := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	public := private.PubKey().SerializeUncompressed()
	requester := keccak(public[1:])[12:]
	domainConfig := defaultSettlementDomain()
	domainConfig.ChainId = 31337
	domainConfig.EscrowAddress = bytes.Repeat([]byte{9}, 20)
	domainConfig.Id = keccak(abiUint64(domainConfig.ChainId), abiAddress(domainConfig.TokenAddress), abiAddress(domainConfig.EscrowAddress), abiAddress(domainConfig.VerifierAddress))
	params := &ProtocolParams{SettlementDomains: []*SettlementDomain{domainConfig}}
	message := &Authorization{SettlementDomainId: domainConfig.Id,
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
	authorization := func(requestID string) *Authorization {
		message := &Authorization{SettlementDomainId: testSettlementDomainID(),
			RequestId: requestID, InputHash: bytes.Repeat([]byte{2}, 32), DirectEoa: true,
			RequestArchiveId: "sha256:0202020202020202020202020202020202020202020202020202020202020202",
			Requester:        bytes.Repeat([]byte{3}, 20), ReservedBudget: 1, OutputType: "boolean",
			OutputMinimum: 0, OutputMaximum: 1,
			Models: testModelBudgets(1, "model"), ExecutionQuorum: 1, DeadlineHeight: 2,
			AuthorizationSignature: []byte{1}, AuthorizationDeadline: 3,
		}
		message.SchemaHash = requestOutputSchemaHash(message)
		return message
	}
	message := &MessageObserveAuthorizations{ObserverAddress: observer, Authorizations: []*Authorization{authorization("one"), authorization("two")}}
	if signer, err := checkObserveAuthorizations(message); err != nil || !bytes.Equal(signer, observer) {
		t.Fatalf("valid batch rejected: signer=%x err=%v", signer, err)
	}
	message.Authorizations[1].RequestId = "one"
	if _, err := checkObserveAuthorizations(message); err == nil {
		t.Fatal("duplicate request was accepted")
	}
	message.Authorizations[1] = authorization("two")
	message.Authorizations[1].DirectEoa = false
	if _, err := checkObserveAuthorizations(message); err == nil {
		t.Fatal("ERC-1271 authorization was accepted in the direct EOA batch")
	}
	message.Authorizations[1] = authorization("two")
	message.Authorizations[1].ReservedBudget = 2
	message.Authorizations[1].Models = testModelBudgets(2, "provider/z", "provider/a")
	message.Authorizations[1].ExecutionQuorum = 2
	if _, err := checkObserveAuthorizations(message); err != nil {
		t.Fatalf("request model order was incorrectly treated as servicer configuration: %v", err)
	}
	message.Authorizations[1].Models = testModelBudgets(2, "provider/z", "provider/z")
	if _, err := checkObserveAuthorizations(message); err == nil {
		t.Fatal("duplicate request models were accepted")
	}
}

func TestVerifyEOARequestAuthorizationsPreservesInputOrder(t *testing.T) {
	params := defaultProtocolParams()
	first := &Authorization{SettlementDomainId: testSettlementDomainID(),
		Requester: bytes.Repeat([]byte{1}, 20), AuthorizationDeadline: 360,
		AuthorizationSignature: make([]byte, 65),
	}
	first.AuthorizationSignature[64] = 9
	second := &Authorization{SettlementDomainId: testSettlementDomainID(), Requester: bytes.Repeat([]byte{2}, 20), AuthorizationDeadline: 360}
	err := verifyEOARequestAuthorizations([]*Authorization{first, second}, params)
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
