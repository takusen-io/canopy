package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"
)

type receipt struct {
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

func (c *Contract) deliverSubmitExecutions(height uint64, message *MessageSubmitExecutions) *PluginDeliverResponse {
	if err := expandExecutionBatch(message); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if err := validateExecutionBatchItems(message); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	authenticated := make([]authenticatedExecution, len(message.Executions))
	var group sync.WaitGroup
	for index, execution := range message.Executions {
		index, execution := index, execution
		group.Add(1)
		go func() {
			defer group.Done()
			parsed, digest, err := parseReceiptSubmission(execution)
			authenticated[index] = authenticatedExecution{parsed: parsed, digest: digest, err: err}
		}()
	}
	group.Wait()
	for _, item := range authenticated {
		if item.err != nil {
			return &PluginDeliverResponse{Error: item.err}
		}
	}
	loaded, loadErr := c.prefetchExecutionState(message.ServicerAddress, authenticated)
	if loadErr != nil {
		return &PluginDeliverResponse{Error: loadErr}
	}
	for index, execution := range message.Executions {
		item := &authenticated[index]
		enclave := new(EnclaveKey)
		if found, readErr := c.readExecutionStaged(nil, loaded, KeyForEnclave(item.parsed.TEEKeyID), enclave); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || enclave.Status != "active" && enclave.Status != "draining" || !bytes.Equal(enclave.OwnerAddress, message.ServicerAddress) ||
			len(enclave.PublicKey) != ed25519.PublicKeySize || !ed25519.Verify(enclave.PublicKey, item.digest, execution.Signature) {
			return &PluginDeliverResponse{Error: ErrCrypto("receipt signature does not match its registered enclave key")}
		}
	}
	records := map[string]proto.Message{}
	var deletes [][]byte
	for index, execution := range message.Executions {
		item := authenticated[index]
		if response := c.stageAuthenticatedExecution(height, message.ServicerAddress, execution, item.parsed, item.digest, records, loaded, &deletes); response.Error != nil {
			return response
		}
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

type authenticatedExecution struct {
	parsed *receipt
	digest []byte
	err    *PluginError
}

func (c *Contract) stageAuthenticatedExecution(height uint64, servicerAddress []byte, message *ExecutionSubmission, parsed *receipt, digest []byte, records, loaded map[string]proto.Message, deletes *[][]byte) *PluginDeliverResponse {
	expectedTEEKeyID := parsed.TEEKeyID
	servicer := new(Servicer)
	if found, readErr := c.readExecutionStaged(records, loaded, KeyForServicer(servicerAddress), servicer); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || !bytes.Equal(servicer.OwnerAddress, servicerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("receipt signer is not a registered servicer")}
	}
	enclave := new(EnclaveKey)
	if found, readErr := c.readExecutionStaged(records, loaded, KeyForEnclave(expectedTEEKeyID), enclave); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || enclave.Status != "active" && enclave.Status != "draining" || !bytes.Equal(enclave.OwnerAddress, servicerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("receipt key is not the registered enclave key")}
	}
	invalid := func(reason *PluginError) *PluginDeliverResponse {
		if servicer.FailureCount == ^uint64(0) {
			return &PluginDeliverResponse{Error: ErrState("servicer failure counter overflow")}
		}
		servicer.FailureCount++
		records[string(KeyForServicer(servicerAddress))] = servicer
		if slashErr := c.applyInvalidReceiptSlash(height, digest, servicer, records, deletes); slashErr != nil {
			return &PluginDeliverResponse{Error: slashErr}
		}
		_ = reason
		return &PluginDeliverResponse{}
	}
	if semanticErr := validateReceipt(parsed, expectedTEEKeyID); semanticErr != nil {
		return invalid(semanticErr)
	}
	existing := new(ExecutionRecord)
	if found, readErr := c.readExecutionStaged(records, loaded, KeyForExecution(parsed.ExecutionID), existing); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found {
		if bytes.Equal(existing.ReceiptDigest, digest) && bytes.Equal(existing.ReceiptSignature, message.Signature) &&
			existing.ArchiveId == parsed.ArchiveID && bytes.Equal(existing.ServicerAddress, servicerAddress) {
			return &PluginDeliverResponse{}
		}
		return &PluginDeliverResponse{Error: ErrConflict("execution identifier has already been committed")}
	}
	request := new(RequestRecord)
	if found, readErr := c.readExecutionStaged(records, loaded, KeyForRequest(parsed.RequestID), request); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || request.Status != "authorized" {
		return &PluginDeliverResponse{Error: ErrNotFound("active request not found")}
	}
	reservation := new(ReservationRecord)
	if found, readErr := c.readExecutionStaged(records, loaded, KeyForReservation(request.SettlementDomainId, request.RequestId), reservation); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || reservation.Status != "reserved" ||
		!bytes.Equal(reservation.Requester, request.Requester) || reservation.Spent > reservation.Budget {
		return &PluginDeliverResponse{Error: ErrState("request reservation cannot record execution spend")}
	}
	inputHash, decodeErr := decodeHash(parsed.InputHash)
	if decodeErr != nil || !bytes.Equal(inputHash, request.InputHash) {
		return invalid(ErrInvalidTransaction("receipt input hash is not authorized"))
	}
	settlementDomain, domainErr := decodeHash(parsed.SettlementDomain)
	if domainErr != nil || !bytes.Equal(settlementDomain, request.SettlementDomainId) {
		return invalid(ErrInvalidTransaction("receipt settlement domain is not authorized"))
	}
	if parsed.Status == "success" {
		if outputErr := validateTypedOutput(request, parsed.Output); outputErr != nil {
			return invalid(outputErr)
		}
	}
	assignment := findAssignment(request, parsed.Model)
	if assignment == nil || assignment.Completed || !bytes.Equal(assignment.ServicerAddress, servicerAddress) {
		return invalid(ErrUnauthorized("execution was not submitted by the assigned servicer"))
	}
	previousAssignments := activeAssignmentOwners(request)
	if assignment.TeeKeyId != "" && assignment.TeeKeyId != parsed.TEEKeyID {
		return invalid(ErrUnauthorized("receipt key is not the enclave key committed to the assignment"))
	}
	if assignment.Provider == "" || parsed.Provider != assignment.Provider {
		return invalid(ErrUnauthorized("receipt provider is not the governed assignment provider"))
	}
	if request.DeadlineHeight == 0 || height > request.DeadlineHeight {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("execution was submitted after its assignment deadline")}
	}
	expectedExecutionID := assignment.ExecutionId
	if expectedExecutionID == "" {
		expectedExecutionID = assignmentExecutionID(request.SettlementDomainId, request.RequestId, assignment.Model, assignment.ServicerAddress, request.InputHash)
	}
	if parsed.ExecutionID != expectedExecutionID {
		return invalid(ErrUnauthorized("receipt execution identifier is not the committed assignment identifier"))
	}
	// A provider failure is not an execution result, and every billable TEE
	// receipt must contain a positive authenticated provider cost. Because the
	// outer transaction and enclave signature bind this evidence to the assigned
	// servicer, a zero-cost/provider-failure receipt is directly slashable in
	// consensus state. The assignment remains incomplete and is retried.
	if parsed.CostMicros == 0 || parsed.Status == "provider_failure" {
		return invalid(ErrInvalidTransaction("receipt has no positive provider cost"))
	}
	modelBudget, modelIndex := budgetForModel(request.Models, parsed.Model)
	if modelIndex < 0 {
		return invalid(ErrInvalidTransaction("receipt model has no snapshotted budget"))
	}
	if request.PricingPolicy == nil {
		return &PluginDeliverResponse{Error: ErrState("request has no pricing policy snapshot")}
	}
	reportedProviderCost := uint64(parsed.CostMicros)
	maximumProviderCost, maximumErr := maxProviderCost(modelBudget, request.PricingPolicy.ServicerMarginBps, request.PricingPolicy.FoundationFeeBps)
	if maximumErr != nil {
		return &PluginDeliverResponse{Error: maximumErr}
	}
	if assignment.MaxProviderCost != maximumProviderCost {
		return &PluginDeliverResponse{Error: ErrState("assignment provider cost limit does not match its snapshotted allocation")}
	}
	if parsed.MaxProviderCostMicros <= 0 || uint64(parsed.MaxProviderCostMicros) != assignment.MaxProviderCost {
		return invalid(ErrInvalidTransaction("receipt provider cost limit does not match the committed assignment"))
	}
	providerCost := reportedProviderCost
	if providerCost <= maximumProviderCost {
		if parsed.Status != "success" && parsed.Status != "non_answer" {
			return invalid(ErrInvalidTransaction("cost within the assignment limit requires a successful or non-answer receipt"))
		}
	} else {
		if parsed.Status != "budget_exhausted" {
			return invalid(ErrInvalidTransaction("cost above the assignment limit requires budget exhaustion"))
		}
		providerCost = maximumProviderCost
	}
	servicerMargin, marginOK := mulDiv64(providerCost, uint64(request.PricingPolicy.ServicerMarginBps), 10_000)
	foundationFee, feeOK := mulDiv64(providerCost, uint64(request.PricingPolicy.FoundationFeeBps), 10_000)
	if !marginOK || !feeOK || ^uint64(0)-providerCost < servicerMargin || ^uint64(0)-(providerCost+servicerMargin) < foundationFee {
		return &PluginDeliverResponse{Error: ErrState("execution charge overflow")}
	}
	chargedCost := providerCost + servicerMargin + foundationFee
	if chargedCost > modelBudget || chargedCost > reservation.Budget-reservation.Spent {
		return invalid(ErrInvalidTransaction("execution exceeds its authorized budget"))
	}
	outputHash, _ := decodeHash(parsed.OutputHash)
	execution := &ExecutionRecord{
		ExecutionId: parsed.ExecutionID, RequestId: parsed.RequestID, Model: parsed.Model,
		Provider:        parsed.Provider,
		ServicerAddress: append([]byte(nil), servicerAddress...), Status: parsed.Status, Output: parsed.Output,
		OutputHash: outputHash, Cost: chargedCost, TeeKeyId: parsed.TEEKeyID,
		ReceiptDigest: digest, ReceiptSignature: append([]byte(nil), message.Signature...), ArchiveId: parsed.ArchiveID, CommittedHeight: height,
		ProviderCost: providerCost, ServicerMargin: servicerMargin, FoundationFee: foundationFee,
		SettlementDomainId: append([]byte(nil), request.SettlementDomainId...),
	}
	assignment.Completed = true
	assignment.ExecutionId = parsed.ExecutionID
	assignment.TerminalStatus = parsed.Status
	reservation.Spent += chargedCost
	records[string(KeyForExecution(parsed.ExecutionID))] = execution
	records[string(KeyForRequest(request.RequestId))] = request
	records[string(KeyForReservation(request.SettlementDomainId, request.RequestId))] = reservation
	if allAssignmentsResolved(request) {
		request.Status = "ready"
		executions, collectErr := c.collectExecutionsStaged(records, request, execution)
		if collectErr != nil {
			return &PluginDeliverResponse{Error: collectErr}
		}
		consensusHash, agreement := agreement(executions)
		request.ConsensusOutputHash = consensusHash
		request.AgreementCount = agreement
	} else {
		// display_agreement_threshold is requester-facing observation metadata only. Every
		// selected assignment continues independently until it returns valid work
		// or exhausts its own retries.
		request.Status = "authorized"
	}
	*deletes = append(*deletes, stageAssignmentIndexes(records, request, previousAssignments)...)
	// Secondary indexes carry only the canonical identity. Storing the complete
	// request here makes a range scan quadratic in practical reconciliation
	// cost as assignment and receipt fields grow. RPC readers resolve these
	// compact pointers to the canonical request key in bounded chunks.
	records[string(KeyForSettlementIndex(request.RequestId))] = &RequestRecord{RequestId: request.RequestId}
	records[string(KeyForUncertifiedSettlementIndex(request.RequestId))] = &RequestRecord{RequestId: request.RequestId}
	// Keep an earlier certificate pinned until its EVM transaction is finalized.
	// Candidate discovery will serialize this new execution behind it, preventing
	// overlapping certificates from paying or publishing the same result twice.
	return &PluginDeliverResponse{}
}

func (c *Contract) readExecutionStaged(records, loaded map[string]proto.Message, key []byte, destination proto.Message) (bool, *PluginError) {
	if staged, ok := records[string(key)]; ok {
		encoded, err := Marshal(staged)
		if err != nil {
			return false, err
		}
		if err = Unmarshal(encoded, destination); err != nil {
			return false, err
		}
		return true, nil
	}
	if cached, ok := loaded[string(key)]; ok {
		if cached == nil {
			return false, nil
		}
		encoded, err := Marshal(cached)
		if err != nil {
			return false, err
		}
		if err = Unmarshal(encoded, destination); err != nil {
			return false, err
		}
		return true, nil
	}
	return c.read(key, destination)
}

func (c *Contract) prefetchExecutionState(servicerAddress []byte, authenticated []authenticatedExecution) (map[string]proto.Message, *PluginError) {
	type target struct {
		key  []byte
		kind byte
	}
	loaded := make(map[string]proto.Message, len(authenticated)*3+2)
	targets := make(map[uint64]target, len(authenticated)*3+2)
	keys := make([]*PluginKeyRead, 0, len(authenticated)*3+2)
	var queryID uint64
	add := func(key []byte, kind byte) {
		encoded := string(key)
		if _, exists := loaded[encoded]; exists {
			return
		}
		loaded[encoded] = nil
		queryID++
		keys = append(keys, &PluginKeyRead{QueryId: queryID, Key: key})
		targets[queryID] = target{key: key, kind: kind}
	}
	add(KeyForServicer(servicerAddress), 1)
	for index := range authenticated {
		parsed := authenticated[index].parsed
		add(KeyForEnclave(parsed.TEEKeyID), 2)
		add(KeyForExecution(parsed.ExecutionID), 3)
		add(KeyForRequest(parsed.RequestID), 4)
		// The signed receipt already commits the settlement domain. Prefetch the
		// reservation with the rest of the cohort so a valid receipt does not pay
		// one synchronous plugin/FSM round trip after its request is decoded.
		if settlementDomain, err := decodeHash(parsed.SettlementDomain); err == nil {
			add(KeyForReservation(settlementDomain, parsed.RequestID), 5)
		}
	}
	// The 256-receipt transaction limit bounds this to at most 1,280 unique
	// keys. Fetch the cohort in one plugin/FSM exchange; splitting it adds IPC
	// latency but no memory-safety or consensus benefit.
	const pageSize = 2048
	for start := 0; start < len(keys); start += pageSize {
		end := min(start+pageSize, len(keys))
		response, err := c.plugin.StateRead(c, &PluginStateReadRequest{Keys: keys[start:end]})
		if err != nil {
			return nil, err
		}
		if response.Error != nil {
			return nil, response.Error
		}
		for _, result := range response.Results {
			target, exists := targets[result.QueryId]
			if !exists || len(result.Entries) == 0 || len(result.Entries[0].Value) == 0 {
				continue
			}
			var destination proto.Message
			switch target.kind {
			case 1:
				destination = new(Servicer)
			case 2:
				destination = new(EnclaveKey)
			case 3:
				destination = new(ExecutionRecord)
			case 4:
				destination = new(RequestRecord)
			case 5:
				destination = new(ReservationRecord)
			}
			if destination == nil {
				return nil, ErrState("unknown execution state prefetch target")
			}
			if decodeErr := Unmarshal(result.Entries[0].Value, destination); decodeErr != nil {
				return nil, decodeErr
			}
			loaded[string(target.key)] = destination
		}
	}
	return loaded, nil
}

func (c *Contract) applyInvalidReceiptSlash(height uint64, receiptDigest []byte, servicer *Servicer, records map[string]proto.Message, deletes *[][]byte) *PluginError {
	evidenceID := hashFields([]byte("takusen:invalid-receipt"), receiptDigest)
	params, err := c.currentProtocolParams()
	if err != nil {
		return err
	}
	return c.applyInvalidReceiptPenalty(height, evidenceID, servicer.OwnerAddress, params, records, deletes)
}

func authenticateReceipt(message *ExecutionSubmission, publicKey []byte) (*receipt, []byte, *PluginError) {
	parsed, digest, parseErr := parseReceiptSubmission(message)
	if parseErr != nil {
		return nil, nil, parseErr
	}
	if !ed25519.Verify(publicKey, digest, message.Signature) {
		return nil, nil, ErrCrypto("receipt signature mismatch")
	}
	return parsed, digest, nil
}

func parseReceiptSubmission(message *ExecutionSubmission) (*receipt, []byte, *PluginError) {
	parsed, parseErr := parseCanonicalReceipt(message.ReceiptJson)
	if parseErr != nil {
		return nil, nil, parseErr
	}
	digest := sha256.Sum256(message.ReceiptJson)
	return parsed, digest[:], nil
}

func parseCanonicalReceipt(encoded []byte) (*receipt, *PluginError) {
	var fields []json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil || len(fields) != 21 {
		return nil, ErrInvalidTransaction("canonical receipt is invalid")
	}
	stringsAt := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 14, 15, 16, 17, 18}
	values := make(map[int]string, len(stringsAt))
	for _, index := range stringsAt {
		var value string
		if err := json.Unmarshal(fields[index], &value); err != nil {
			return nil, ErrInvalidTransaction("canonical receipt string is invalid")
		}
		values[index] = value
	}
	integers := make(map[int]int64, 6)
	for _, index := range []int{10, 11, 12, 13, 19, 20} {
		var value string
		if err := json.Unmarshal(fields[index], &value); err != nil {
			return nil, ErrInvalidTransaction("canonical receipt integer is invalid")
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, ErrInvalidTransaction("canonical receipt integer is invalid")
		}
		integers[index] = parsed
	}
	parsed := &receipt{
		Domain: values[0], ExecutionID: values[1], RequestID: values[2], InputHash: values[3], SettlementDomain: values[4],
		Model: values[5], Provider: values[6], Status: values[7], Output: values[8], OutputHash: values[9],
		PromptTokens: integers[10], CompletionTokens: integers[11], CostMicros: integers[12], MaxProviderCostMicros: integers[13],
		ProviderRequestHash: values[14], ProviderResponseHash: values[15], ArchiveID: values[16],
		ExecutionNonce: values[17], TEEKeyID: values[18], StartedAtMS: integers[19], CompletedAtMS: integers[20],
	}
	canonical, _ := json.Marshal([]any{
		parsed.Domain,
		parsed.ExecutionID, parsed.RequestID, parsed.InputHash, parsed.SettlementDomain, parsed.Model, parsed.Provider, parsed.Status, parsed.Output, parsed.OutputHash,
		strconv.FormatInt(parsed.PromptTokens, 10), strconv.FormatInt(parsed.CompletionTokens, 10), strconv.FormatInt(parsed.CostMicros, 10),
		strconv.FormatInt(parsed.MaxProviderCostMicros, 10), parsed.ProviderRequestHash, parsed.ProviderResponseHash, parsed.ArchiveID, parsed.ExecutionNonce, parsed.TEEKeyID,
		strconv.FormatInt(parsed.StartedAtMS, 10), strconv.FormatInt(parsed.CompletedAtMS, 10),
	})
	if !bytes.Equal(canonical, encoded) {
		return nil, ErrInvalidTransaction("receipt encoding is not canonical")
	}
	return parsed, nil
}

func verifyReceipt(message *ExecutionSubmission, publicKey []byte) (*receipt, []byte, *PluginError) {
	parsed, digest, err := authenticateReceipt(message, publicKey)
	if err != nil {
		return nil, nil, err
	}
	keyDigest := sha256.Sum256(publicKey)
	if semanticErr := validateReceipt(parsed, "ed25519:"+hex.EncodeToString(keyDigest[:])); semanticErr != nil {
		return nil, nil, semanticErr
	}
	return parsed, digest, nil
}

func validateReceipt(parsed *receipt, expectedTEEKeyID string) *PluginError {
	if parsed.Domain != "takusen:execution-receipt" || parsed.ExecutionID == "" || len(parsed.ExecutionID) > 128 || parsed.RequestID == "" || parsed.Model == "" || parsed.Provider == "" ||
		parsed.CostMicros < 0 || parsed.MaxProviderCostMicros <= 0 || parsed.PromptTokens < 0 || parsed.CompletionTokens < 0 || parsed.StartedAtMS <= 0 || parsed.CompletedAtMS < parsed.StartedAtMS {
		return ErrInvalidTransaction("receipt fields are invalid")
	}
	if _, err := decodeHash(parsed.InputHash); err != nil {
		return ErrInvalidTransaction("receipt input hash is invalid")
	}
	if _, err := decodeHash(parsed.SettlementDomain); err != nil {
		return ErrInvalidTransaction("receipt settlement domain is invalid")
	}
	for _, hash := range []string{parsed.OutputHash, parsed.ProviderRequestHash, parsed.ProviderResponseHash, parsed.ExecutionNonce} {
		if _, err := decodeHash(hash); err != nil {
			return ErrInvalidTransaction("receipt commitment is invalid")
		}
	}
	if !validArchiveID(parsed.ArchiveID) {
		return ErrInvalidTransaction("receipt archive commitment mismatch")
	}
	outputDigest := sha256.Sum256([]byte(parsed.Output))
	if parsed.OutputHash != "0x"+hex.EncodeToString(outputDigest[:]) {
		return ErrInvalidTransaction("receipt output hash mismatch")
	}
	switch parsed.Status {
	case "success":
	case "budget_exhausted", "non_answer", "provider_failure":
		if parsed.Output != "" {
			return ErrInvalidTransaction("non-answer receipt contains an output")
		}
		if parsed.Status == "provider_failure" && parsed.CostMicros != 0 {
			return ErrInvalidTransaction("provider failure cannot charge execution cost")
		}
	default:
		return ErrInvalidTransaction("receipt status is invalid")
	}
	if parsed.TEEKeyID != expectedTEEKeyID {
		return ErrInvalidTransaction("receipt TEE key identifier mismatch")
	}
	return nil
}

func validArchiveID(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func maxProviderCost(grossBudget uint64, marginBps, feeBps uint32) (uint64, *PluginError) {
	low, high := uint64(0), grossBudget
	for low < high {
		mid := low + (high-low+1)/2
		margin, marginOK := mulDiv64(mid, uint64(marginBps), 10_000)
		fee, feeOK := mulDiv64(mid, uint64(feeBps), 10_000)
		fits := marginOK && feeOK && ^uint64(0)-mid >= margin && ^uint64(0)-(mid+margin) >= fee && mid+margin+fee <= grossBudget
		if fits {
			low = mid
		} else {
			high = mid - 1
		}
	}
	if low == 0 {
		return 0, ErrInvalidTransaction("model allocation cannot fund a positive provider charge")
	}
	return low, nil
}

func validateTypedOutput(request *RequestRecord, value string) *PluginError {
	switch request.OutputType {
	case "boolean":
		if value == "true" || value == "false" {
			return nil
		}
	case "choice":
		if len(value) == 1 && int64(value[0]) >= request.OutputMinimum && int64(value[0]) <= request.OutputMaximum {
			return nil
		}
	case "score":
		if score, err := strconv.Atoi(value); err == nil && int64(score) >= request.OutputMinimum && int64(score) <= request.OutputMaximum && strconv.Itoa(score) == value {
			return nil
		}
	case "private_hash":
		if decoded, err := decodeHash(value); err == nil && len(decoded) == sha256.Size {
			return nil
		}
	}
	return ErrInvalidTransaction("receipt output does not match the authorized type")
}

func decodeHash(value string) ([]byte, error) {
	if len(value) != 66 || !strings.HasPrefix(value, "0x") {
		return nil, hex.ErrLength
	}
	return hex.DecodeString(value[2:])
}

func budgetForModel(values []*ModelBudget, wanted string) (uint64, int) {
	for index, value := range values {
		if value != nil && value.Model == wanted {
			return value.Budget, index
		}
	}
	return 0, -1
}

func completedExecutions(request *RequestRecord) int {
	count := 0
	for _, assignment := range request.Assignments {
		if assignment.Completed && assignment.ExecutionId != "" && assignment.TerminalStatus != "timeout" {
			count++
		}
	}
	return count
}

func allAssignmentsResolved(request *RequestRecord) bool {
	for _, assignment := range request.Assignments {
		if !assignment.Completed {
			return false
		}
	}
	return true
}

func (c *Contract) collectExecutions(request *RequestRecord, current *ExecutionRecord) ([]*ExecutionRecord, *PluginError) {
	return c.collectExecutionsStaged(nil, request, current)
}

func (c *Contract) collectExecutionsStaged(records map[string]proto.Message, request *RequestRecord, current *ExecutionRecord) ([]*ExecutionRecord, *PluginError) {
	executions := make([]*ExecutionRecord, 0, completedExecutions(request))
	for _, assignment := range request.Assignments {
		if !assignment.Completed || assignment.ExecutionId == "" || assignment.TerminalStatus == "timeout" {
			continue
		}
		if current != nil && assignment.ExecutionId == current.ExecutionId {
			executions = append(executions, current)
			continue
		}
		execution := new(ExecutionRecord)
		if found, err := c.readStaged(records, KeyForExecution(assignment.ExecutionId), execution); err != nil {
			return nil, err
		} else if !found {
			return nil, ErrState("completed assignment has no execution record")
		}
		executions = append(executions, execution)
	}
	return executions, nil
}

func agreement(executions []*ExecutionRecord) ([]byte, uint32) {
	counts := make(map[string]uint32)
	var best []byte
	var bestCount uint32
	for _, execution := range executions {
		if execution.Status != "success" {
			continue
		}
		key := string(execution.OutputHash)
		counts[key]++
		if counts[key] > bestCount || counts[key] == bestCount && bytes.Compare(execution.OutputHash, best) < 0 {
			best = append([]byte(nil), execution.OutputHash...)
			bestCount = counts[key]
		}
	}
	return best, bestCount
}
