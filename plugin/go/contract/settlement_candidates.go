package contract

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

const settlementType = "Settlement(bytes32 executionId,bytes32 requestId,bytes32 modelId,address requester,address servicer,bytes32 output,uint8 outputType,uint8 status,uint96 cost,uint96 servicerPayment,uint96 foundationFee,uint128 requestBudget,uint128 requestSpent,bool finalizesRequest,bytes32 inputHash,bytes32 modelSetHash,bytes32 schemaHash,uint64 deadline,uint16 expectedModels,bytes32 modelIdsHash)"
const settlementBatchType = "SettlementBatch(bytes32 settlementDomain,uint64 validatorSetId,uint64 batchNonce,bytes32 settlementsHash)"

type certifiedSettlementExecution struct {
	ExecutionID           string `json:"executionID"`
	Model                 string `json:"model"`
	Servicer              string `json:"servicer"`
	Output                string `json:"output"`
	OutputType            string `json:"outputType"`
	Status                string `json:"status"`
	CostMicros            int64  `json:"costMicros"`
	ServicerPaymentMicros int64  `json:"servicerPaymentMicros"`
	FoundationFeeMicros   int64  `json:"foundationFeeMicros"`
	FoundationFeeBps      uint32 `json:"foundationFeeBps"`
}

type certifiedSettlementRequest struct {
	SettlementDomain string                         `json:"settlementDomain"`
	RequestID        string                         `json:"requestID"`
	InputHash        string                         `json:"inputHash"`
	Models           []string                       `json:"models"`
	OutputType       string                         `json:"outputType"`
	OutputSchema     certifiedSettlementSchema      `json:"outputSchema"`
	Deadline         uint64                         `json:"deadline"`
	Requester        string                         `json:"requester"`
	ReservedBudget   uint64                         `json:"reservedBudget"`
	RequestSpent     uint64                         `json:"requestSpent"`
	Executions       []certifiedSettlementExecution `json:"executions"`
	FinalizesRequest bool                           `json:"finalizesRequest"`
}

type certifiedSettlementSchema struct {
	Minimum int64    `json:"minimum"`
	Maximum int64    `json:"maximum"`
	Choices []string `json:"choices,omitempty"`
}

type certifiedSettlementBatch struct {
	ValidatorSetID uint64                       `json:"validatorSetId"`
	BatchNonce     uint64                       `json:"batchNonce"`
	Digest         string                       `json:"digest"`
	Requests       []certifiedSettlementRequest `json:"requests"`
}

func (c *Contract) settlementAuxiliaryCandidates(clock *EpochClock, limit int) ([]*AuxiliaryCandidate, *PluginError) {
	if limit <= 0 {
		return nil, nil
	}
	entries, err := c.rangeReadPage(SettlementIndexPrefix(), nil, 256)
	if err != nil {
		return nil, err
	}
	result := make([]*AuxiliaryCandidate, 0, min(limit, len(entries)))
	for _, entry := range entries {
		if len(result) == limit {
			break
		}
		pointer := new(RequestRecord)
		if Unmarshal(entry.Value, pointer) != nil || pointer.RequestId == "" {
			continue
		}
		request := new(RequestRecord)
		if found, readErr := c.read(KeyForRequest(pointer.RequestId), request); readErr != nil {
			return nil, readErr
		} else if !found || request.Status != "authorized" && request.Status != "ready" || len(request.SettlementDomainId) != 32 || len(request.Requester) != 20 || len(request.InputHash) != 32 {
			continue
		}
		reservation := new(ReservationRecord)
		if found, readErr := c.read(KeyForReservation(request.SettlementDomainId, request.RequestId), reservation); readErr != nil {
			return nil, readErr
		} else if !found || reservation.Status != "reserved" {
			continue
		}
		candidate := certifiedSettlementRequest{
			SettlementDomain: "0x" + hex.EncodeToString(request.SettlementDomainId), RequestID: request.RequestId,
			InputHash: "0x" + hex.EncodeToString(request.InputHash), Models: append([]string(nil), request.Models...),
			OutputType: request.OutputType, OutputSchema: certifiedSettlementSchema{Minimum: request.OutputMinimum, Maximum: request.OutputMaximum, Choices: append([]string(nil), request.OutputChoices...)},
			Deadline: request.DeadlineHeight, Requester: "0x" + hex.EncodeToString(request.Requester), ReservedBudget: reservation.Budget, RequestSpent: reservation.Spent,
			FinalizesRequest: allAssignmentsResolved(request),
		}
		var executionIDs []string
		for _, assignment := range request.Assignments {
			if assignment == nil || !assignment.Completed || assignment.ExecutionId == "" {
				continue
			}
			execution := new(ExecutionRecord)
			if found, readErr := c.read(KeyForExecution(assignment.ExecutionId), execution); readErr != nil {
				return nil, readErr
			} else if !found || execution.Settled || execution.RequestId != request.RequestId || execution.Model != assignment.Model {
				continue
			}
			servicer := new(Servicer)
			if found, readErr := c.read(KeyForServicer(execution.ServicerAddress), servicer); readErr != nil {
				return nil, readErr
			} else if !found {
				continue
			}
			payout := settlementPayout(servicer, request.SettlementDomainId)
			if len(payout) != 20 || execution.Cost > uint64(^uint64(0)>>1) || execution.ProviderCost > uint64(^uint64(0)>>1) || execution.ServicerMargin > uint64(^uint64(0)>>1) || execution.FoundationFee > uint64(^uint64(0)>>1) || ^uint64(0)-execution.ProviderCost < execution.ServicerMargin {
				continue
			}
			candidate.Executions = append(candidate.Executions, certifiedSettlementExecution{
				ExecutionID: execution.ExecutionId, Model: execution.Model, Servicer: "0x" + hex.EncodeToString(payout),
				Output: execution.Output, OutputType: request.OutputType, Status: execution.Status,
				CostMicros: int64(execution.Cost), ServicerPaymentMicros: int64(execution.ProviderCost + execution.ServicerMargin),
				FoundationFeeMicros: int64(execution.FoundationFee), FoundationFeeBps: request.FoundationFeeBps,
			})
			executionIDs = append(executionIDs, execution.ExecutionId)
		}
		if len(candidate.Executions) == 0 {
			continue
		}
		identityKey := hashFields([]byte(request.RequestId), stringListBytes(executionIDs), boolBytes(candidate.FinalizesRequest))
		batchNonce := binary.BigEndian.Uint64(identityKey[:8])
		if batchNonce == 0 {
			batchNonce = 1
		}
		key := uint64Bytes(batchNonce)
		digest, digestErr := settlementAuthorizationDigest(clock.ValidatorSetId, batchNonce, candidate)
		if digestErr != nil {
			continue
		}
		payload, marshalErr := json.Marshal(certifiedSettlementBatch{ValidatorSetID: clock.ValidatorSetId, BatchNonce: batchNonce, Digest: "0x" + hex.EncodeToString(digest), Requests: []certifiedSettlementRequest{candidate}})
		if marshalErr != nil || len(payload) > 16<<10 {
			continue
		}
		result = append(result, &AuxiliaryCandidate{Kind: "settlement", Key: key, Digest: digest, Payload: payload})
	}
	return result, nil
}

func settlementPayout(servicer *Servicer, domainID []byte) []byte {
	for _, payout := range servicer.Payouts {
		if payout != nil && string(payout.SettlementDomainId) == string(domainID) {
			return payout.Address
		}
	}
	return nil
}

func settlementAuthorizationDigest(validatorSetID, batchNonce uint64, request certifiedSettlementRequest) ([]byte, error) {
	modelIDs := make([][]byte, len(request.Models))
	modelArray := append(abiUint64(32), abiUint64(uint64(len(request.Models)))...)
	for index, model := range request.Models {
		digest := sha256.Sum256([]byte(model))
		modelIDs[index] = digest[:]
		modelArray = append(modelArray, digest[:]...)
	}
	modelSetHash := keccak256(modelArray)
	modelIDsHash := modelSetHash
	requestID := sha256.Sum256([]byte(request.RequestID))
	itemHashes := make([]byte, 0, 32*len(request.Executions))
	for index, execution := range request.Executions {
		executionID := sha256.Sum256([]byte(execution.ExecutionID))
		modelID := sha256.Sum256([]byte(execution.Model))
		outputType, output, ok := settlementOutput(request, execution)
		if !ok {
			return nil, ErrInvalidTransaction("invalid settlement output")
		}
		status := uint64(1)
		switch execution.Status {
		case "success":
		case "budget_exhausted":
			status = 2
		case "failed":
			status = 3
		default:
			return nil, ErrInvalidTransaction("invalid settlement status")
		}
		encoded := make([]byte, 0, 32*21)
		encoded = append(encoded, keccak256([]byte(settlementType))...)
		encoded = append(encoded, executionID[:]...)
		encoded = append(encoded, requestID[:]...)
		encoded = append(encoded, modelID[:]...)
		encoded = append(encoded, abiAddress(mustHex(request.Requester, 20))...)
		encoded = append(encoded, abiAddress(mustHex(execution.Servicer, 20))...)
		encoded = append(encoded, output...)
		for _, value := range []uint64{outputType, status, uint64(execution.CostMicros), uint64(execution.ServicerPaymentMicros), uint64(execution.FoundationFeeMicros), request.ReservedBudget, request.RequestSpent} {
			encoded = append(encoded, abiUint64(value)...)
		}
		encoded = append(encoded, abiUint64(boolUint64(request.FinalizesRequest && index == len(request.Executions)-1))...)
		encoded = append(encoded, mustHex(request.InputHash, 32)...)
		encoded = append(encoded, modelSetHash...)
		encoded = append(encoded, requestSchemaHash(request)...)
		encoded = append(encoded, abiUint64(request.Deadline)...)
		encoded = append(encoded, abiUint64(uint64(len(request.Models)))...)
		encoded = append(encoded, modelIDsHash...)
		itemHashes = append(itemHashes, keccak256(encoded)...)
	}
	domain := mustHex(request.SettlementDomain, 32)
	if len(domain) != 32 {
		return nil, ErrInvalidTransaction("invalid settlement domain")
	}
	encoded := append([]byte{}, keccak256([]byte(settlementBatchType))...)
	encoded = append(encoded, domain...)
	encoded = append(encoded, abiUint64(validatorSetID)...)
	encoded = append(encoded, abiUint64(batchNonce)...)
	encoded = append(encoded, keccak256(itemHashes)...)
	return keccak256(encoded), nil
}

func settlementOutput(request certifiedSettlementRequest, execution certifiedSettlementExecution) (uint64, []byte, bool) {
	word := make([]byte, 32)
	switch request.OutputType {
	case "boolean":
		if execution.Output == "true" {
			word[31] = 1
		} else if execution.Output != "false" && execution.Status == "success" {
			return 0, nil, false
		}
		return 1, word, true
	case "score":
		value, err := strconv.ParseUint(execution.Output, 10, 8)
		if execution.Status == "success" && (err != nil || int64(value) < request.OutputSchema.Minimum || int64(value) > request.OutputSchema.Maximum) {
			return 0, nil, false
		}
		word[31] = byte(value)
		return 2, word, true
	case "choice":
		if execution.Status == "success" && (len(execution.Output) != 1 || int64(execution.Output[0]) < request.OutputSchema.Minimum || int64(execution.Output[0]) > request.OutputSchema.Maximum) {
			return 0, nil, false
		}
		if len(execution.Output) == 1 {
			word[31] = execution.Output[0]
		}
		return 3, word, true
	case "private_hash":
		decoded := mustHex(execution.Output, 32)
		if execution.Status == "success" && len(decoded) != 32 {
			return 0, nil, false
		}
		copy(word, decoded)
		return 4, word, true
	}
	return 0, nil, false
}

func requestSchemaHash(request certifiedSettlementRequest) []byte {
	message := &MessageObserveAuthorization{OutputType: request.OutputType, OutputMinimum: request.OutputSchema.Minimum, OutputMaximum: request.OutputSchema.Maximum, OutputChoices: request.OutputSchema.Choices}
	return requestOutputSchemaHash(message)
}

func mustHex(value string, size int) []byte {
	decoded, _ := hex.DecodeString(trimHex(value))
	if len(decoded) != size {
		return nil
	}
	return decoded
}

func trimHex(value string) string {
	if len(value) >= 2 && value[:2] == "0x" {
		return value[2:]
	}
	return value
}

func boolUint64(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}
