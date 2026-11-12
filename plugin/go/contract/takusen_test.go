package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const testRequestArchiveID = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func testSettlementDomainID() []byte {
	return append([]byte(nil), defaultSettlementDomain().Id...)
}

func testPCRPolicy() *PCRPolicy {
	return &PCRPolicy{Pcr0: bytes.Repeat([]byte{1}, 48), Pcr1: bytes.Repeat([]byte{2}, 48), Pcr2: bytes.Repeat([]byte{3}, 48), Active: true}
}

func TestGenesisPersistsProtocolParameters(t *testing.T) {
	contract, _, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision = 1
	params.ApprovedPcrs = []*PCRPolicy{testPCRPolicy()}
	encoded, err := protojson.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(map[string]any{"pluginGenesis": map[string]json.RawMessage{"takusen": encoded}})
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.Genesis(&PluginGenesisRequest{GenesisJson: document}); response.Error != nil {
		t.Fatal(response.Error)
	}
	stored := new(ProtocolParams)
	if found, readErr := contract.read(KeyForProtocolParams(), stored); readErr != nil || !found || stored.Revision != 1 {
		t.Fatalf("genesis parameters missing: found=%v err=%v params=%#v", found, readErr, stored)
	}
	if response := contract.Genesis(&PluginGenesisRequest{GenesisJson: []byte(`{}`)}); response.Error == nil {
		t.Fatal("accepted genesis without Takusen parameters")
	}
}

func TestAssignmentIsStableAndRotates(t *testing.T) {
	servicers := []*Servicer{{OwnerAddress: []byte{1}}, {OwnerAddress: []byte{2}}, {OwnerAddress: []byte{3}}}
	input := make([]byte, 32)
	anchor := make([]byte, 32)
	first := selectServicer(input, anchor, "model", 0, servicers)
	if first != selectServicer(input, anchor, "model", 0, servicers) {
		t.Fatal("assignment is not deterministic")
	}
	second := selectServicer(input, anchor, "model", 1, servicers)
	if string(first.OwnerAddress) == string(second.OwnerAddress) {
		t.Fatal("reassignment did not rotate to the next eligible servicer")
	}
}

func TestAssignmentIndexTracksOnlyActiveOwners(t *testing.T) {
	first, second := bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 20)
	request := &RequestRecord{SettlementDomainId: testSettlementDomainID(), RequestId: "request", Status: "authorized", Assignments: []*Assignment{
		{Model: "first", ServicerAddress: first},
		{Model: "second", ServicerAddress: second, TerminalStatus: "awaiting_servicer"},
	}}
	records := make(map[string]proto.Message)
	if deletes := stageAssignmentIndexes(records, request, nil); len(deletes) != 0 || len(records) != 1 {
		t.Fatalf("initial index records=%d deletes=%d", len(records), len(deletes))
	}
	for _, indexed := range records {
		if pointer, ok := indexed.(*RequestRecord); !ok || pointer.RequestId != request.RequestId || len(pointer.Assignments) != 0 {
			t.Fatalf("assignment index is not a compact request pointer: %#v", indexed)
		}
	}
	request.Assignments[0].Completed = true
	deletes := stageAssignmentIndexes(records, request, map[string][]byte{string(first): first})
	if len(deletes) != 1 || !bytes.Equal(deletes[0], KeyForAssignmentIndex(first, request.RequestId)) {
		t.Fatalf("completed assignment deletes=%x", deletes)
	}
}

func TestVerifyReceipt(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	outputDigest := sha256.Sum256([]byte("true"))
	commitment := "0x" + hex.EncodeToString(outputDigest[:])
	archiveID := "sha256:" + strings.Repeat("ab", 32)
	keyDigest := sha256.Sum256(publicKey)
	r := receipt{
		Domain:      "takusen:execution-receipt",
		ExecutionID: "execution", RequestID: "request", InputHash: commitment, SettlementDomain: "0x" + hex.EncodeToString(testSettlementDomainID()), Model: "model",
		Provider: "provider", Status: "success", Output: "true", OutputHash: commitment, PromptTokens: 10, CompletionTokens: 1,
		CostMicros: 42, MaxProviderCostMicros: 100, ProviderRequestHash: commitment, ProviderResponseHash: commitment, ArchiveID: archiveID,
		ExecutionNonce: commitment, TEEKeyID: "ed25519:" + hex.EncodeToString(keyDigest[:]),
		StartedAtMS: 1, CompletedAtMS: 2,
	}
	canonical, _ := json.Marshal([]any{
		r.Domain,
		r.ExecutionID, r.RequestID, r.InputHash, r.SettlementDomain, r.Model, r.Provider, r.Status, r.Output, r.OutputHash,
		strconv.FormatInt(r.PromptTokens, 10), strconv.FormatInt(r.CompletionTokens, 10), strconv.FormatInt(r.CostMicros, 10),
		strconv.FormatInt(r.MaxProviderCostMicros, 10), r.ProviderRequestHash, r.ProviderResponseHash, r.ArchiveID, r.ExecutionNonce, r.TEEKeyID,
		strconv.FormatInt(r.StartedAtMS, 10), strconv.FormatInt(r.CompletedAtMS, 10),
	})
	digest := sha256.Sum256(canonical)
	message := &MessageSubmitExecution{
		ServicerAddress: make([]byte, 20), ReceiptJson: canonical, PublicKey: publicKey,
		Signature: ed25519.Sign(privateKey, digest[:]), ArchiveId: archiveID,
	}
	parsed, verifiedDigest, verifyErr := verifyReceipt(message)
	if verifyErr != nil {
		t.Fatal(verifyErr)
	}
	if parsed.ExecutionID != r.ExecutionID || hex.EncodeToString(verifiedDigest) != hex.EncodeToString(digest[:]) {
		t.Fatal("verified receipt differs from signed receipt")
	}
	message.ReceiptJson = append([]byte(nil), canonical...)
	message.ReceiptJson[1] ^= 0x01
	if _, _, verifyErr = verifyReceipt(message); verifyErr == nil {
		t.Fatal("tampered canonical receipt was accepted")
	}
	message.ReceiptJson = canonical
	message.Signature[0] ^= 0xff
	if _, _, verifyErr = verifyReceipt(message); verifyErr == nil {
		t.Fatal("tampered receipt signature was accepted")
	}
}

func TestMaximumProviderCostFitsAllInModelAllocation(t *testing.T) {
	maximum, err := maxProviderCost(100_000, 1_000, 500)
	if err != nil {
		t.Fatal(err)
	}
	margin, _ := mulDiv64(maximum, 1_000, 10_000)
	fee, _ := mulDiv64(maximum, 500, 10_000)
	if maximum+margin+fee > 100_000 {
		t.Fatalf("maximum provider cost exceeds all-in allocation: %d", maximum+margin+fee)
	}
	nextMargin, _ := mulDiv64(maximum+1, 1_000, 10_000)
	nextFee, _ := mulDiv64(maximum+1, 500, 10_000)
	if maximum+1+nextMargin+nextFee <= 100_000 {
		t.Fatalf("maximum provider cost was not maximal: %d", maximum)
	}
}

func TestObservationSubjectsExcludeObserverOnly(t *testing.T) {
	message := &MessageObserveAuthorization{SettlementDomainId: testSettlementDomainID(),
		ObserverAddress: make([]byte, 20), RequestId: "request", InputHash: make([]byte, 32),
		Requester: make([]byte, 20), ReservedBudget: 100, OutputType: "boolean", Models: []string{"model"},
		ExecutionQuorum: 1, DeadlineHeight: 100,
	}
	first := authorizationSubject(message)
	message.ObserverAddress[0] = 1
	second := authorizationSubject(message)
	if string(first) != string(second) {
		t.Fatal("observer identity changed the observed authorization subject")
	}
	message.ReservedBudget++
	if string(first) == string(authorizationSubject(message)) {
		t.Fatal("authorization content did not change its subject")
	}
	message.ReservedBudget--
	message.AuthorizationChainBlockNumber = 7
	message.AuthorizationChainBlockHash = bytes.Repeat([]byte{9}, 32)
	if string(first) == string(authorizationSubject(message)) {
		t.Fatal("ERC-1271 Base block evidence did not change the authorization subject")
	}
}

func TestDepositSubjectAndCreditInvariant(t *testing.T) {
	message := &MessageObserveDeposit{ObserverAddress: make([]byte, 20), SettlementDomainId: testSettlementDomainID(), ChainTxHash: make([]byte, 32), Requester: make([]byte, 20), AmountMicros: 100, TokenAmount: []byte{100}}
	first := depositSubject(message)
	message.ObserverAddress[0] = 1
	if string(first) != string(depositSubject(message)) {
		t.Fatal("observer identity changed the observed deposit subject")
	}
	message.AmountMicros++
	if string(first) == string(depositSubject(message)) {
		t.Fatal("deposit content did not change its subject")
	}
	if available, valid := availableCredit(&CreditAccount{SettlementDomainId: testSettlementDomainID(), Deposited: 100, Reserved: 30, Settled: 20}); !valid || available != 50 {
		t.Fatalf("available credit = %d, valid = %v", available, valid)
	}
	if _, valid := availableCredit(&CreditAccount{SettlementDomainId: testSettlementDomainID(), Deposited: 100, Reserved: 90, Settled: 20}); valid {
		t.Fatal("accepted an overcommitted credit account")
	}
}

func TestSafeAvailableCreditExcludesFlashblockDeposits(t *testing.T) {
	account := &CreditAccount{SettlementDomainId: testSettlementDomainID(), Deposited: 150, Provisional: 100, Reserved: 0, Settled: 0}
	if available, valid := availableCredit(account); !valid || available != 150 {
		t.Fatalf("total available credit=%d valid=%t", available, valid)
	}
	if available, valid := safeAvailableCredit(account); !valid || available != 50 {
		t.Fatalf("safe available credit=%d valid=%t", available, valid)
	}
}

func TestSettlementSubjectBindsTransactionAndBudget(t *testing.T) {
	message := &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(),
		ObserverAddress: make([]byte, 20), RequestId: "request", SettlementTxHash: make([]byte, 32),
		ReservedBudget: 100, ExecutionIds: []string{"execution"}, FinalizesRequest: true,
	}
	first := settlementSubject(message)
	message.ObserverAddress[0] = 1
	if string(first) != string(settlementSubject(message)) {
		t.Fatal("observer identity changed the settlement subject")
	}
	message.ReservedBudget++
	if string(first) == string(settlementSubject(message)) {
		t.Fatal("reservation budget did not change the settlement subject")
	}
	message.ReservedBudget--
	message.SettlementTxHash[0] = 1
	if string(first) == string(settlementSubject(message)) {
		t.Fatal("settlement transaction did not change the settlement subject")
	}
	message.SettlementTxHash[0] = 0
	message.ExecutionIds[0] = "other"
	if string(first) == string(settlementSubject(message)) {
		t.Fatal("execution identifiers did not change the settlement subject")
	}
}

func TestSettlementBatchSubjectAndValidationBindEveryMember(t *testing.T) {
	first := &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(), RequestId: "one", SettlementTxHash: bytes.Repeat([]byte{1}, 32), ReservedBudget: 100, RequestSpent: 40, ExecutionIds: []string{"execution-one"}, FinalizesRequest: true}
	second := &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(), RequestId: "two", SettlementTxHash: bytes.Repeat([]byte{2}, 32), ReservedBudget: 200, RequestSpent: 50, ExecutionIds: []string{"execution-two"}, FinalizesRequest: true}
	digest := settlementBatchSubject([]*MessageFinalizeRequest{first, second})
	if bytes.Equal(digest, settlementBatchSubject([]*MessageFinalizeRequest{second, first})) {
		t.Fatal("finalization batch order was not bound")
	}
	changed := proto.Clone(second).(*MessageFinalizeRequest)
	changed.RequestSpent++
	if bytes.Equal(digest, settlementBatchSubject([]*MessageFinalizeRequest{first, changed})) {
		t.Fatal("finalization batch member contents were not bound")
	}
	batch := &MessageFinalizeRequests{
		ObserverAddress: bytes.Repeat([]byte{9}, 20), Requests: []*MessageFinalizeRequest{first, second},
		ValidatorSetId: 1, SignerBitmap: []byte{7}, AggregateSignature: []byte{8},
	}
	if _, err := checkFinalizeRequests(batch); err != nil {
		t.Fatal(err)
	}
	batch.Requests = append(batch.Requests, first)
	if _, err := checkFinalizeRequests(batch); err == nil {
		t.Fatal("duplicate finalization batch member was accepted")
	}
}

func TestGovernedParamsRejectUnsafeValues(t *testing.T) {
	valid := defaultProtocolParams()
	valid.Revision = 1
	valid.ApprovedPcrs = []*PCRPolicy{testPCRPolicy()}
	if err := validateProtocolParams(valid); err != nil {
		t.Fatal(err)
	}
	invalidQuorum := proto.Clone(valid).(*ProtocolParams)
	invalidQuorum.QuorumNumerator = 3
	invalidQuorum.QuorumDenominator = 5
	if err := validateProtocolParams(invalidQuorum); err == nil {
		t.Fatal("accepted a quorum threshold below two thirds")
	}
	impossibleQuorum := proto.Clone(valid).(*ProtocolParams)
	impossibleQuorum.QuorumNumerator = impossibleQuorum.QuorumDenominator
	if err := validateProtocolParams(impossibleQuorum); err == nil {
		t.Fatal("accepted an unreachable quorum threshold")
	}
	missingValidatorBond := proto.Clone(valid).(*ProtocolParams)
	missingValidatorBond.MinimumValidatorBond = 0
	if err := validateProtocolParams(missingValidatorBond); err == nil {
		t.Fatal("accepted a zero minimum validator bond")
	}
	missingPCRs := proto.Clone(valid).(*ProtocolParams)
	missingPCRs.ApprovedPcrs = nil
	if err := validateProtocolParams(missingPCRs); err == nil {
		t.Fatal("accepted an empty governed PCR allowlist")
	}
	inactivePCRs := proto.Clone(valid).(*ProtocolParams)
	inactivePCRs.ApprovedPcrs[0].Active = false
	if err := validateProtocolParams(inactivePCRs); err == nil {
		t.Fatal("accepted a governed PCR allowlist with no active policy")
	}
	if pcrApproved(&ProtocolParams{}, bytes.Repeat([]byte{1}, 48), bytes.Repeat([]byte{2}, 48), bytes.Repeat([]byte{3}, 48)) {
		t.Fatal("empty consensus PCR policy approved an enclave")
	}
	for bank := 0; bank < 3; bank++ {
		zeroPCR := proto.Clone(valid).(*ProtocolParams)
		switch bank {
		case 0:
			zeroPCR.ApprovedPcrs[0].Pcr0 = make([]byte, 48)
		case 1:
			zeroPCR.ApprovedPcrs[0].Pcr1 = make([]byte, 48)
		case 2:
			zeroPCR.ApprovedPcrs[0].Pcr2 = make([]byte, 48)
		}
		if err := validateProtocolParams(zeroPCR); err == nil {
			t.Fatalf("accepted all-zero PCR bank %d", bank)
		}
		if pcrApproved(zeroPCR, zeroPCR.ApprovedPcrs[0].Pcr0, zeroPCR.ApprovedPcrs[0].Pcr1, zeroPCR.ApprovedPcrs[0].Pcr2) {
			t.Fatalf("consensus approved all-zero PCR bank %d", bank)
		}
	}
	duplicateModels := proto.Clone(valid).(*ProtocolParams)
	duplicateModels.Models = []*ModelParams{
		{Model: "model", Provider: "provider", Active: true},
		{Model: "model", Provider: "provider", Active: true},
	}
	if err := validateProtocolParams(duplicateModels); err == nil {
		t.Fatal("accepted duplicate governed models")
	}
	lowDecimalToken := proto.Clone(valid).(*ProtocolParams)
	lowDecimalToken.SettlementDomains[0].TokenDecimals = 4
	if err := validateProtocolParams(lowDecimalToken); err == nil {
		t.Fatal("accepted a governed token with fewer than six decimals")
	}
	if _, ok := normalizeTokenAmount([]byte{1}, 4); ok {
		t.Fatal("normalized a token with fewer than six decimals")
	}
}

func TestBridgeReleaseDigestMatchesSolidityABI(t *testing.T) {
	params := &ProtocolParams{
		CanonicalChainId: 8453, CanonicalBridgeAddress: bytes.Repeat([]byte{0x11}, 20), ValidatorSetId: 7,
	}
	digest := bridgeReleaseDigest(params, 7, 9, bytes.Repeat([]byte{0x22}, 20), 123, bytes.Repeat([]byte{0xaa}, 32))
	if got := "0x" + hex.EncodeToString(digest); got != "0xf1ef0fcefcc4b5d2851b9809469bb86c326fc5bf2a8e8d6850e40fc99fb17981" {
		t.Fatalf("bridge digest = %s", got)
	}
}

func TestEpochAuthorizationDigestMatchesSolidityABI(t *testing.T) {
	params := &ProtocolParams{
		CanonicalChainId: 8453, CanonicalTokenAddress: bytes.Repeat([]byte{0x44}, 20), ValidatorSetId: 7,
	}
	digest := epochAuthorizationDigest(params, 7, 5, [][]byte{bytes.Repeat([]byte{0x22}, 20), bytes.Repeat([]byte{0x33}, 20)}, []uint64{100, 20})
	if got := "0x" + hex.EncodeToString(digest); got != "0xcaa7c62240f7b95ba96771c2493180ebe65a7240d8e7010e1b6a977c757239c5" {
		t.Fatalf("epoch digest = %s", got)
	}
}

func TestSettlementFinalizationDigestMatchesApplication(t *testing.T) {
	message := &MessageFinalizeRequest{
		SettlementDomainId: bytes.Repeat([]byte{0xaa}, 32), RequestId: "request-vector",
		SettlementTxHash: bytes.Repeat([]byte{0xbb}, 32), ReservedBudget: 100_000, RequestSpent: 42_000,
		ExecutionIds: []string{"exec-a", "exec-b"}, FinalizesRequest: true,
	}
	if got := hex.EncodeToString(settlementSubject(message)); got != "783d4727a509a69377adb4fb8fffb799475e6038650fa7752a640145e4855315" {
		t.Fatalf("single finalization digest = %s", got)
	}
	if got := hex.EncodeToString(settlementBatchSubject([]*MessageFinalizeRequest{message})); got != "237be5d42aa947dc8e23f1c0d6fbe29a0b29004057096d80520cfd27cefefdde" {
		t.Fatalf("batch finalization digest = %s", got)
	}
}
