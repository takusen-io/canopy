package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/canopy-network/go-plugin/contract"
	plugincrypto "github.com/canopy-network/go-plugin/crypto"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/drand/kyber"
	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bdn"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	localValidatorOneAddress = "851e90eaef1fa27debaee2c2591503bdeec1d123"
	localValidatorTwoAddress = "02cd4e5eb53ea665702042a6ed6d31d616054dc5"
	localValidatorOneKey     = "6c275055a4f6ae6bccf1e6552e172c7b8cc538a7b8d2dd645125df9e25c9ed2d"
	localValidatorTwoKey     = "0add1e53f45d439b98182216a9215db238aaff12d1b057b3130b0c5e8e9b0b36"
)

type localSigner struct {
	address string
	key     *plugincrypto.BLS12381PrivateKey
}

type testReceipt struct {
	Domain                string `json:"domain"`
	ExecutionID           string `json:"executionId"`
	RequestID             string `json:"requestId"`
	InputHash             string `json:"inputHash"`
	SettlementDomain      string `json:"settlementDomain"`
	Model                 string `json:"model"`
	Provider              string `json:"provider"`
	Status                string `json:"status"`
	Output                string `json:"output"`
	OutputHash            string `json:"outputHash"`
	PromptTokens          int64  `json:"promptTokens"`
	CompletionTokens      int64  `json:"completionTokens"`
	CostMicros            int64  `json:"costMicros"`
	MaxProviderCostMicros int64  `json:"maxProviderCostMicros"`
	ProviderRequestHash   string `json:"providerRequestHash"`
	ProviderResponseHash  string `json:"providerResponseHash"`
	ArchiveID             string `json:"archiveId"`
	ExecutionNonce        string `json:"executionNonce"`
	TEEKeyID              string `json:"teeKeyId"`
	StartedAtMS           int64  `json:"startedAtMs"`
	CompletedAtMS         int64  `json:"completedAtMs"`
}

func e2eHashFields(fields ...[]byte) []byte {
	hasher := sha256.New()
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write(field)
	}
	return hasher.Sum(nil)
}

func e2eUint64(value uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return encoded
}

func e2eKeccak(fields ...[]byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	for _, field := range fields {
		_, _ = hasher.Write(field)
	}
	return hasher.Sum(nil)
}

func e2eABIUint64(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}

func e2eABIAddress(address []byte) []byte {
	word := make([]byte, 32)
	copy(word[12:], address)
	return word
}

func e2eStringList(values []string) []byte {
	fields := make([][]byte, len(values))
	for index := range values {
		fields[index] = []byte(values[index])
	}
	return e2eHashFields(fields...)
}

func e2eSettlementBatchSubject(messages []*contract.RequestFinalization) []byte {
	fields := make([][]byte, 1, len(messages)+1)
	fields[0] = []byte("takusen:settlement-finalization-batch")
	for _, message := range messages {
		fields = append(fields, e2eHashFields(
			[]byte("takusen:settlement-finalization"), message.SettlementDomainId, []byte(message.RequestId),
			message.SettlementTxHash, e2eUint64(message.ReservedBudget), e2eUint64(message.RequestSpent),
			e2eStringList(message.ExecutionIds), []byte{1},
		))
	}
	return e2eHashFields(fields...)
}

func e2eValidatorCertificate(t *testing.T, digest []byte, validators ...localSigner) ([]byte, []byte) {
	t.Helper()
	// The development fixture gives both validators equal stake, so consensus
	// order is descending raw address.
	slices.SortFunc(validators, func(left, right localSigner) int {
		return -bytes.Compare(mustHex(t, left.address), mustHex(t, right.address))
	})
	suite := drandbls.NewBLS12381Suite()
	points := make([]kyber.Point, len(validators))
	for index, validator := range validators {
		points[index] = suite.G1().Point().Mul(validator.key.Scalar, nil)
	}
	mask, err := sign.NewMask(suite, points, nil)
	if err != nil {
		t.Fatal(err)
	}
	scheme := bdn.NewSchemeOnG2(suite)
	partials := make([][]byte, len(validators))
	for index, validator := range validators {
		if err = mask.SetBit(index, true); err != nil {
			t.Fatal(err)
		}
		if partials[index], err = scheme.Sign(validator.key.Scalar, digest); err != nil {
			t.Fatal(err)
		}
	}
	aggregate, err := scheme.AggregateSignatures(partials, mask)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := aggregate.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return mask.Mask(), encoded
}

// TestTakusenConsensusE2E exercises the complete native Takusen state machine
// against the two-node development network. It is opt-in because it requires
// plugin/go/compose.yaml to be running.
func TestTakusenConsensusE2E(t *testing.T) {
	if os.Getenv("TAKUSEN_E2E") != "1" {
		t.Skip("set TAKUSEN_E2E=1 with the local Canopy compose network running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	rpcURL := envOr("TAKUSEN_CANOPY_RPC_URL", "http://127.0.0.1:50002")
	pluginURL := envOr("TAKUSEN_CANOPY_PLUGIN_URL", "http://127.0.0.1:50010")
	status, paramsBody := getStatus(ctx, pluginURL+"/v1/takusen/params")
	params := new(contract.ProtocolParams)
	if status != http.StatusOK || json.Unmarshal(paramsBody, params) != nil || len(params.SettlementDomains) == 0 || len(params.SettlementDomains[0].Id) != 32 {
		t.Fatalf("governed settlement domain is unavailable: HTTP %d: %s", status, paramsBody)
	}
	settlementDomain := params.SettlementDomains[0].Id
	validatorOne := mustSigner(t, localValidatorOneAddress, envOr("TAKUSEN_VALIDATOR_ONE_KEY", localValidatorOneKey))
	validatorTwo := mustSigner(t, localValidatorTwoAddress, envOr("TAKUSEN_VALIDATOR_TWO_KEY", localValidatorTwoKey))
	requesterKey := secp256k1.PrivKeyFromBytes(bytes.Repeat([]byte{7}, 32))
	requesterAddress := e2eKeccak(requesterKey.PubKey().SerializeUncompressed()[1:])[12:]

	seed := sha256.Sum256([]byte("takusen-local-e2e-enclave"))
	enclaveKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := enclaveKey.Public().(ed25519.PublicKey)
	keyDigest := sha256.Sum256(publicKey)
	teeKeyID := "ed25519:" + hex.EncodeToString(keyDigest[:])
	models := []string{"openai/gpt-6-luna", "anthropic/claude-haiku-5.5", "google/gemini-3.8-flash"}

	if !servicerExists(t, ctx, pluginURL, localValidatorOneAddress) {
		var bundle struct {
			Attestation string `json:"attestation"`
			Nonce       string `json:"nonce"`
			UserData    string `json:"userData"`
			PublicKey   string `json:"publicKey"`
			Proof       string `json:"proof"`
		}
		encodedBundle := os.Getenv("TAKUSEN_E2E_REGISTRATION_BUNDLE")
		if encodedBundle == "" || json.Unmarshal([]byte(encodedBundle), &bundle) != nil {
			t.Fatal("TAKUSEN_E2E_REGISTRATION_BUNDLE must contain fresh complete owner-bound Nitro evidence when the E2E enclave is not registered")
		}
		attestation, attestationErr := base64.StdEncoding.DecodeString(bundle.Attestation)
		nonce, nonceErr := base64.StdEncoding.DecodeString(bundle.Nonce)
		userData, userDataErr := base64.StdEncoding.DecodeString(bundle.UserData)
		attestedPublicKey, publicKeyErr := base64.RawURLEncoding.DecodeString(bundle.PublicKey)
		proof, proofErr := base64.RawURLEncoding.DecodeString(bundle.Proof)
		expectedUserData := []byte("takusen:servicer-registration:v1:" + localValidatorOneAddress)
		registration := sha256.New()
		_, _ = registration.Write([]byte("takusen:nitro-registration\x00"))
		_, _ = registration.Write(nonce)
		_, _ = registration.Write([]byte{0})
		_, _ = registration.Write(userData)
		if attestationErr != nil || nonceErr != nil || userDataErr != nil || publicKeyErr != nil || proofErr != nil ||
			len(attestation) == 0 || len(attestation) > 16<<10 || !bytes.Equal(attestedPublicKey, publicKey) ||
			!bytes.Equal(userData, expectedUserData) || !ed25519.Verify(publicKey, registration.Sum(nil), proof) {
			t.Fatal("TAKUSEN_E2E_REGISTRATION_BUNDLE is invalid or does not bind the fixture owner and enclave key")
		}
		message := &contract.MessageManageServicer{
			OwnerAddress: mustHex(t, localValidatorOneAddress), TeeKeyId: teeKeyID, PublicKey: publicKey,
			Nonce: nonce, UserData: userData, ProofSignature: proof, AttestationDocument: attestation,
			EvmPayoutAddress: mustHex(t, localValidatorOneAddress), Models: models, Bond: 100_000, Active: true,
		}
		fields := map[string]any{
			"ownerAddress": localValidatorOneAddress, "teeKeyId": teeKeyID, "publicKey": hex.EncodeToString(publicKey),
			"nonce": hex.EncodeToString(nonce), "userData": hex.EncodeToString(userData), "proofSignature": hex.EncodeToString(proof),
			"attestationDocument": hex.EncodeToString(attestation), "evmPayoutAddress": localValidatorOneAddress, "models": models, "bond": message.Bond, "active": true,
		}
		submit(t, ctx, rpcURL, validatorOne, contract.MessageManageServicerName, message, fields)
		waitStatus(t, ctx, pluginURL+"/v1/takusen/servicers", func(body []byte) bool { return containsServicer(body, localValidatorOneAddress) })
	}

	requestID := fmt.Sprintf("canopy-e2e-%d", time.Now().UnixNano())
	inputHash := sha256.Sum256([]byte(requestID + ":input"))
	chainDepositHash := sha256.Sum256([]byte(requestID + ":chain-deposit"))
	observeDeposit := func(address string) (*contract.MessageObserveDeposit, map[string]any) {
		message := &contract.MessageObserveDeposit{
			ObserverAddress: mustHex(t, address), SettlementDomainId: settlementDomain, ChainTxHash: chainDepositHash[:],
			Requester: requesterAddress, AmountMicros: 1_000_000, TokenAmount: []byte{0x0f, 0x42, 0x40},
		}
		return message, map[string]any{
			"observerAddress": address, "settlementDomainId": hex.EncodeToString(settlementDomain), "chainTxHash": hex.EncodeToString(chainDepositHash[:]),
			"requester": hex.EncodeToString(requesterAddress), "amountMicros": message.AmountMicros, "tokenAmount": hex.EncodeToString(message.TokenAmount),
		}
	}
	deposit, depositFields := observeDeposit(validatorOne.address)
	submit(t, ctx, rpcURL, validatorOne, contract.MessageObserveDepositName, deposit, depositFields)
	deposit, depositFields = observeDeposit(validatorTwo.address)
	submit(t, ctx, rpcURL, validatorTwo, contract.MessageObserveDepositName, deposit, depositFields)
	waitStatus(t, ctx, pluginURL+"/v1/takusen/domains/"+hex.EncodeToString(settlementDomain)+"/deposits/"+hex.EncodeToString(chainDepositHash[:]), func(body []byte) bool {
		var value contract.DepositRecord
		return json.Unmarshal(body, &value) == nil && value.Amount == 1_000_000
	})

	height := currentHeight(t, ctx, rpcURL)
	observeAuthorization := func() (*contract.Authorization, map[string]any) {
		message := &contract.Authorization{
			SettlementDomainId: settlementDomain, RequestId: requestID, InputHash: inputHash[:], Requester: requesterAddress,
			ReservedBudget: 100_000, OutputType: "boolean", Models: []string{models[0]}, ExecutionQuorum: 1,
			DeadlineHeight: height + 100, AuthorizationDeadline: height + 100, DirectEoa: true,
			RequestArchiveId: "sha256:" + hex.EncodeToString(inputHash[:]), OutputMinimum: 0, OutputMaximum: 1,
		}
		message.SchemaHash = e2eKeccak(e2eABIUint64(1), e2eABIUint64(0), e2eABIUint64(1), make([]byte, 32))
		domain := e2eKeccak(
			e2eKeccak([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")),
			e2eKeccak([]byte("Takusen Escrow")), e2eKeccak([]byte("1")), e2eABIUint64(params.SettlementDomains[0].ChainId), e2eABIAddress(params.SettlementDomains[0].EscrowAddress),
		)
		requestHash := sha256.Sum256([]byte(message.RequestId))
		structure := e2eKeccak(
			e2eKeccak([]byte("AuthorizeRequest(bytes32 requestId,bytes32 inputHash,bytes32 settlementDomain,address requester,uint128 budget,uint64 deadline)")),
			requestHash[:], message.InputHash, message.SettlementDomainId, e2eABIAddress(message.Requester), e2eABIUint64(message.ReservedBudget), e2eABIUint64(message.AuthorizationDeadline),
		)
		compact := secpECDSA.SignCompact(requesterKey, e2eKeccak([]byte{0x19, 0x01}, domain, structure), false)
		message.AuthorizationSignature = append(append([]byte(nil), compact[1:]...), compact[0]-27)
		return message, map[string]any{
			"requestId": requestID, "settlementDomainId": hex.EncodeToString(settlementDomain), "inputHash": hex.EncodeToString(inputHash[:]), "requester": hex.EncodeToString(requesterAddress),
			"reservedBudget": message.ReservedBudget, "outputType": message.OutputType, "models": message.Models,
			"executionQuorum": message.ExecutionQuorum, "deadlineHeight": message.DeadlineHeight,
			"authorizationSignature": hex.EncodeToString(message.AuthorizationSignature), "authorizationDeadline": message.AuthorizationDeadline,
			"directEoa": true, "requestArchiveId": message.RequestArchiveId, "outputMinimum": message.OutputMinimum,
			"outputMaximum": message.OutputMaximum, "schemaHash": hex.EncodeToString(message.SchemaHash),
		}
	}
	message, fields := observeAuthorization()
	batch := &contract.MessageObserveAuthorizations{ObserverAddress: mustHex(t, validatorOne.address), Authorizations: []*contract.Authorization{message}}
	submit(t, ctx, rpcURL, validatorOne, contract.MessageObserveAuthorizationsName, batch, map[string]any{
		"observerAddress": validatorOne.address, "authorizations": []any{fields},
	})
	requestURL := pluginURL + "/v1/takusen/requests/" + requestID
	var committedRequest contract.RequestRecord
	waitStatus(t, ctx, requestURL, func(body []byte) bool {
		return json.Unmarshal(body, &committedRequest) == nil && committedRequest.Status == "authorized" && len(committedRequest.Assignments) == 1
	})

	executionID := committedRequest.Assignments[0].ExecutionId
	started := time.Now().Add(-time.Second).UnixMilli()
	receipt := testReceipt{
		Domain:      "takusen:execution-receipt",
		ExecutionID: executionID, RequestID: requestID, InputHash: "0x" + hex.EncodeToString(inputHash[:]), SettlementDomain: "0x" + hex.EncodeToString(settlementDomain), Model: models[0], Provider: committedRequest.Assignments[0].Provider, Status: "success", Output: "true",
		PromptTokens: 12, CompletionTokens: 1, CostMicros: 5_000, MaxProviderCostMicros: int64(committedRequest.Assignments[0].MaxProviderCost), TEEKeyID: teeKeyID, StartedAtMS: started, CompletedAtMS: started + 500,
	}
	outputHash := sha256.Sum256([]byte(receipt.Output))
	providerRequestHash := sha256.Sum256([]byte(requestID + ":provider-request"))
	providerResponseHash := sha256.Sum256([]byte(requestID + ":provider-response"))
	executionNonce := sha256.Sum256([]byte(requestID + ":nonce"))
	receipt.OutputHash = "0x" + hex.EncodeToString(outputHash[:])
	receipt.ProviderRequestHash = "0x" + hex.EncodeToString(providerRequestHash[:])
	receipt.ProviderResponseHash = "0x" + hex.EncodeToString(providerResponseHash[:])
	archiveDigest := sha256.Sum256([]byte(requestID + ":archive"))
	receipt.ArchiveID = "sha256:" + hex.EncodeToString(archiveDigest[:])
	receipt.ExecutionNonce = "0x" + hex.EncodeToString(executionNonce[:])
	canonical, _ := json.Marshal([]any{
		receipt.Domain,
		receipt.ExecutionID, receipt.RequestID, receipt.InputHash, receipt.SettlementDomain, receipt.Model, receipt.Provider, receipt.Status, receipt.Output, receipt.OutputHash,
		strconv.FormatInt(receipt.PromptTokens, 10), strconv.FormatInt(receipt.CompletionTokens, 10), strconv.FormatInt(receipt.CostMicros, 10),
		strconv.FormatInt(receipt.MaxProviderCostMicros, 10), receipt.ProviderRequestHash, receipt.ProviderResponseHash, receipt.ArchiveID, receipt.ExecutionNonce, receipt.TEEKeyID,
		strconv.FormatInt(receipt.StartedAtMS, 10), strconv.FormatInt(receipt.CompletedAtMS, 10),
	})
	receiptDigest := sha256.Sum256(canonical)
	receiptSignature := ed25519.Sign(enclaveKey, receiptDigest[:])
	execution := &contract.ExecutionSubmission{ReceiptJson: canonical, Signature: receiptSignature}
	executionBatch := &contract.MessageSubmitExecutions{
		ServicerAddress: mustHex(t, localValidatorOneAddress),
		Executions: []*contract.ExecutionSubmission{execution},
	}
	executionFields := map[string]any{
		"servicerAddress": localValidatorOneAddress,
		"executions": []any{map[string]any{
			"receiptJson": hex.EncodeToString(canonical), "signature": hex.EncodeToString(receiptSignature),
		}},
	}
	submit(t, ctx, rpcURL, validatorOne, contract.MessageSubmitExecutionsName, executionBatch, executionFields)
	waitStatus(t, ctx, requestURL, func(body []byte) bool {
		var value contract.RequestRecord
		return json.Unmarshal(body, &value) == nil && value.Status == "ready"
	})

	settlementHash := sha256.Sum256([]byte(requestID + ":settlement"))
	observeSettlement := func() (*contract.RequestFinalization, map[string]any) {
		message := &contract.RequestFinalization{
			SettlementDomainId: settlementDomain, RequestId: requestID, SettlementTxHash: settlementHash[:],
			ReservedBudget: 100_000, RequestSpent: uint64(receipt.CostMicros), ExecutionIds: []string{executionID}, FinalizesRequest: true,
		}
		return message, map[string]any{
			"settlementDomainId": hex.EncodeToString(settlementDomain), "requestId": requestID, "settlementTxHash": hex.EncodeToString(settlementHash[:]),
			"reservedBudget": message.ReservedBudget, "requestSpent": message.RequestSpent, "executionIds": message.ExecutionIds, "finalizesRequest": true,
		}
	}
	finalize, finalizeFields := observeSettlement()
	bitmap, aggregate := e2eValidatorCertificate(t, e2eSettlementBatchSubject([]*contract.RequestFinalization{finalize}), validatorOne, validatorTwo)
	finalizationBatch := &contract.MessageFinalizeRequests{
		ObserverAddress: mustHex(t, validatorOne.address), Requests: []*contract.RequestFinalization{finalize},
		ValidatorSetId: params.ValidatorSetId, SignerBitmap: bitmap, AggregateSignature: aggregate,
	}
	submit(t, ctx, rpcURL, validatorOne, contract.MessageFinalizeRequestsName, finalizationBatch, map[string]any{
		"observerAddress": validatorOne.address, "requests": []any{finalizeFields}, "validatorSetId": params.ValidatorSetId,
		"signerBitmap": hex.EncodeToString(bitmap), "aggregateSignature": hex.EncodeToString(aggregate),
	})
	waitStatus(t, ctx, requestURL, func(body []byte) bool {
		var value contract.RequestRecord
		return json.Unmarshal(body, &value) == nil && value.Status == "settled" &&
			bytes.Equal(value.SettlementTxHash, settlementHash[:])
	})
	waitStatus(t, ctx, pluginURL+"/v1/takusen/domains/"+hex.EncodeToString(settlementDomain)+"/reservations/"+requestID, func(body []byte) bool {
		var value contract.ReservationRecord
		return json.Unmarshal(body, &value) == nil && value.Status == "released" &&
			value.Spent == uint64(receipt.CostMicros) && value.Released == 100_000-uint64(receipt.CostMicros)
	})
	t.Logf("Takusen request %s completed through two-validator Canopy consensus", requestID)
}

func mustSigner(t *testing.T, address, privateKey string) localSigner {
	t.Helper()
	key, err := plugincrypto.StringToBLS12381PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return localSigner{address: address, key: key}
}

func submit(t *testing.T, ctx context.Context, rpcURL string, signer localSigner, messageType string, message proto.Message, fields map[string]any) string {
	t.Helper()
	height := currentHeight(t, ctx, rpcURL)
	fee := currentPluginFee(t, ctx, rpcURL)
	txTime := uint64(time.Now().UnixMicro())
	wrapped, err := anypb.New(message)
	if err != nil {
		t.Fatal(err)
	}
	signBytes, err := plugincrypto.GetSignBytes(messageType, wrapped, txTime, height, fee, "", 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"type": messageType, "msg": fields,
		"signature": map[string]string{"publicKey": hex.EncodeToString(signer.key.PublicKey().Bytes()), "signature": hex.EncodeToString(signer.key.Sign(signBytes))},
		"time":      txTime, "createdHeight": height, "fee": fee, "memo": "", "networkID": 1, "chainID": 1,
	}
	encoded, _ := json.Marshal(payload)
	body := postJSON(t, ctx, rpcURL+"/v1/tx", encoded)
	var hash string
	if err = json.Unmarshal(body, &hash); err != nil {
		t.Fatalf("decode transaction response %s: %v", body, err)
	}
	return hash
}

func currentPluginFee(t *testing.T, ctx context.Context, rpcURL string) uint64 {
	t.Helper()
	body := postJSON(t, ctx, rpcURL+"/v1/query/fee-params", []byte(`{"height":0}`))
	var value struct {
		SendFee uint64 `json:"sendFee"`
	}
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	if value.SendFee == 0 {
		return 1
	}
	return value.SendFee
}

func currentHeight(t *testing.T, ctx context.Context, rpcURL string) uint64 {
	t.Helper()
	body := postJSON(t, ctx, rpcURL+"/v1/query/height", []byte("{}"))
	var value struct {
		Height uint64 `json:"height"`
	}
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value.Height
}

func postJSON(t *testing.T, ctx context.Context, url string, body []byte) []byte {
	t.Helper()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	result, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode/100 != 2 {
		t.Fatalf("POST %s returned HTTP %d: %s", url, resp.StatusCode, result)
	}
	return result
}

func waitStatus(t *testing.T, ctx context.Context, url string, ready func([]byte) bool) {
	t.Helper()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, body := getStatus(ctx, url)
		if status == http.StatusOK && ready(body) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s (last HTTP %d: %s)", url, status, body)
		case <-ticker.C:
		}
	}
}

func getStatus(ctx context.Context, url string) (int, []byte) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, []byte(err.Error())
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return resp.StatusCode, body
}

func servicerExists(t *testing.T, ctx context.Context, pluginURL, address string) bool {
	t.Helper()
	status, body := getStatus(ctx, pluginURL+"/v1/takusen/servicers")
	if status != http.StatusOK {
		t.Fatalf("query servicers returned HTTP %d: %s", status, body)
	}
	return containsServicer(body, address)
}

func containsServicer(body []byte, address string) bool {
	var values []*contract.Servicer
	if json.Unmarshal(body, &values) != nil {
		return false
	}
	for _, value := range values {
		if hex.EncodeToString(value.OwnerAddress) == address && value.Active {
			return true
		}
	}
	return false
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
