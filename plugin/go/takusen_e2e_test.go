package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/canopy-network/go-plugin/contract"
	plugincrypto "github.com/canopy-network/go-plugin/crypto"
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

	seed := sha256.Sum256([]byte("takusen-local-e2e-enclave"))
	enclaveKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := enclaveKey.Public().(ed25519.PublicKey)
	keyDigest := sha256.Sum256(publicKey)
	teeKeyID := "ed25519:" + hex.EncodeToString(keyDigest[:])
	models := []string{"openai/gpt-6-luna", "anthropic/claude-haiku-5.5", "google/gemini-3.8-flash"}

	if status, _ := getStatus(ctx, pluginURL+"/v1/takusen/enclaves/"+teeKeyID); status == http.StatusNotFound {
		nonce := []byte("takusen-local-e2e-nonce")
		userData := []byte("takusen-local-e2e")
		registration := sha256.New()
		_, _ = registration.Write([]byte("takusen:nitro-registration\x00"))
		_, _ = registration.Write(nonce)
		_, _ = registration.Write([]byte{0})
		_, _ = registration.Write(userData)
		attestation := sha256.Sum256([]byte("local-nitro-attestation"))
		observe := func(address string) (*contract.MessageObserveEnclave, map[string]any) {
			message := &contract.MessageObserveEnclave{
				ObserverAddress: mustHex(t, address), OwnerAddress: mustHex(t, localValidatorOneAddress),
				TeeKeyId: teeKeyID, PublicKey: publicKey, AttestationHash: attestation[:],
				Pcr0: bytes.Repeat([]byte{0x10}, 48), Pcr1: bytes.Repeat([]byte{0x11}, 48), Pcr2: bytes.Repeat([]byte{0x12}, 48),
				Nonce: nonce, UserData: userData, ProofSignature: ed25519.Sign(enclaveKey, registration.Sum(nil)),
			}
			return message, map[string]any{
				"observerAddress": hex.EncodeToString(message.ObserverAddress), "ownerAddress": hex.EncodeToString(message.OwnerAddress),
				"teeKeyId": message.TeeKeyId, "publicKey": hex.EncodeToString(message.PublicKey), "attestationHash": hex.EncodeToString(message.AttestationHash),
				"pcr0": hex.EncodeToString(message.Pcr0), "pcr1": hex.EncodeToString(message.Pcr1), "pcr2": hex.EncodeToString(message.Pcr2),
				"nonce": hex.EncodeToString(message.Nonce), "userData": hex.EncodeToString(message.UserData), "proofSignature": hex.EncodeToString(message.ProofSignature),
			}
		}
		message, fields := observe(validatorOne.address)
		submit(t, ctx, rpcURL, validatorOne, contract.MessageObserveEnclaveName, message, fields)
		message, fields = observe(validatorTwo.address)
		submit(t, ctx, rpcURL, validatorTwo, contract.MessageObserveEnclaveName, message, fields)
		waitStatus(t, ctx, pluginURL+"/v1/takusen/enclaves/"+teeKeyID, func(body []byte) bool {
			var value contract.EnclaveKey
			return json.Unmarshal(body, &value) == nil && value.Active
		})
	}

	if !servicerExists(t, ctx, pluginURL, localValidatorOneAddress) {
		payouts := []*contract.SettlementPayout{{SettlementDomainId: settlementDomain, Address: mustHex(t, localValidatorOneAddress)}}
		message := &contract.MessageRegisterServicer{OwnerAddress: mustHex(t, localValidatorOneAddress), Payouts: payouts, TeeKeyId: teeKeyID, Models: models, Bond: 100_000}
		fields := map[string]any{"ownerAddress": localValidatorOneAddress, "payouts": payouts, "teeKeyId": teeKeyID, "models": models, "bond": message.Bond}
		submit(t, ctx, rpcURL, validatorOne, contract.MessageRegisterServicerName, message, fields)
		waitStatus(t, ctx, pluginURL+"/v1/takusen/servicers", func(body []byte) bool { return containsServicer(body, localValidatorOneAddress) })
	}

	requestID := fmt.Sprintf("canopy-e2e-%d", time.Now().UnixNano())
	inputHash := sha256.Sum256([]byte(requestID + ":input"))
	chainDepositHash := sha256.Sum256([]byte(requestID + ":chain-deposit"))
	observeDeposit := func(address string) (*contract.MessageObserveDeposit, map[string]any) {
		message := &contract.MessageObserveDeposit{
			ObserverAddress: mustHex(t, address), SettlementDomainId: settlementDomain, ChainTxHash: chainDepositHash[:],
			Requester: mustHex(t, localValidatorOneAddress), AmountMicros: 1_000_000, TokenAmount: []byte{0x0f, 0x42, 0x40},
		}
		return message, map[string]any{
			"observerAddress": address, "settlementDomainId": hex.EncodeToString(settlementDomain), "chainTxHash": hex.EncodeToString(chainDepositHash[:]),
			"requester": localValidatorOneAddress, "amountMicros": message.AmountMicros, "tokenAmount": hex.EncodeToString(message.TokenAmount),
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
	observeAuthorization := func(address string) (*contract.MessageObserveAuthorization, map[string]any) {
		message := &contract.MessageObserveAuthorization{
			ObserverAddress: mustHex(t, address), SettlementDomainId: settlementDomain, RequestId: requestID, InputHash: inputHash[:], Requester: mustHex(t, localValidatorOneAddress),
			ReservedBudget: 100_000, OutputType: "boolean", Models: []string{models[0]}, ExecutionQuorum: 1,
			DeadlineHeight: height + 100, AuthorizationSignature: []byte{1}, AuthorizationDeadline: 9_007_199_254_740_991,
		}
		return message, map[string]any{
			"observerAddress": address, "requestId": requestID, "inputHash": hex.EncodeToString(inputHash[:]), "requester": localValidatorOneAddress,
			"reservedBudget": message.ReservedBudget, "outputType": message.OutputType, "models": message.Models,
			"executionQuorum": message.ExecutionQuorum, "deadlineHeight": message.DeadlineHeight,
			"authorizationSignature": hex.EncodeToString(message.AuthorizationSignature), "authorizationDeadline": message.AuthorizationDeadline,
		}
	}
	message, fields := observeAuthorization(validatorOne.address)
	submit(t, ctx, rpcURL, validatorOne, contract.MessageObserveAuthorizationName, message, fields)
	message, fields = observeAuthorization(validatorTwo.address)
	submit(t, ctx, rpcURL, validatorTwo, contract.MessageObserveAuthorizationName, message, fields)
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
	execution := &contract.MessageSubmitExecution{ServicerAddress: mustHex(t, localValidatorOneAddress), ReceiptJson: canonical, PublicKey: publicKey, Signature: receiptSignature, ArchiveId: receipt.ArchiveID}
	executionFields := map[string]any{
		"servicerAddress": localValidatorOneAddress, "receiptJson": hex.EncodeToString(canonical), "publicKey": hex.EncodeToString(publicKey),
		"signature": hex.EncodeToString(receiptSignature), "archiveId": execution.ArchiveId,
	}
	submit(t, ctx, rpcURL, validatorOne, contract.MessageSubmitExecutionName, execution, executionFields)
	waitStatus(t, ctx, requestURL, func(body []byte) bool {
		var value contract.RequestRecord
		return json.Unmarshal(body, &value) == nil && value.Status == "ready"
	})

	settlementHash := sha256.Sum256([]byte(requestID + ":settlement"))
	observeSettlement := func(address string) (*contract.MessageFinalizeRequest, map[string]any) {
		message := &contract.MessageFinalizeRequest{
			ObserverAddress: mustHex(t, address), SettlementDomainId: settlementDomain, RequestId: requestID, SettlementTxHash: settlementHash[:],
			ReservedBudget: 100_000, RequestSpent: uint64(receipt.CostMicros), ExecutionIds: []string{executionID}, FinalizesRequest: true,
		}
		return message, map[string]any{
			"observerAddress": address, "settlementDomainId": hex.EncodeToString(settlementDomain), "requestId": requestID, "settlementTxHash": hex.EncodeToString(settlementHash[:]),
			"reservedBudget": message.ReservedBudget, "requestSpent": message.RequestSpent, "executionIds": message.ExecutionIds, "finalizesRequest": true,
		}
	}
	finalize, finalizeFields := observeSettlement(validatorOne.address)
	submit(t, ctx, rpcURL, validatorOne, contract.MessageFinalizeRequestName, finalize, finalizeFields)
	finalize, finalizeFields = observeSettlement(validatorTwo.address)
	submit(t, ctx, rpcURL, validatorTwo, contract.MessageFinalizeRequestName, finalize, finalizeFields)
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
