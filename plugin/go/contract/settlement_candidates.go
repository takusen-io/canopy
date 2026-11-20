package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"

	"google.golang.org/protobuf/proto"
)

const (
	maxSettlementRequestsPerCertificate   = 64
	maxSettlementExecutionsPerCertificate = 64
	// Keep authorization and finalization independently bounded below half of
	// the global 64-certificate ceiling, while admitting enough concurrent
	// cohorts that fragmented domain-ready batches cannot throttle settlement.
	maxSettlementCertificatesPerBlock = 16
	settlementCandidatePageSize       = uint64(1024)
)

const requestInitializationType = "RequestInitialization(bytes32 requestId,bytes32 inputHash,bytes32 modelSetHash,bytes32 schemaHash,address requester,uint96 requestBudget,uint64 deadline,uint8 outputType,bytes32 modelIdsHash)"
const requestChunkType = "RequestSettlementChunk(bytes32 requestId,bytes32 requestCommitment,uint96 requestSpent,uint16 requesterIndex,bytes32 packedResultsHash)"
const requestCommitmentType = "RequestCommitmentV5(bytes32 requestId,bytes32 inputHash,bytes32 modelSetHash,bytes32 schemaHash,address requester,uint96 requestBudget,uint64 deadline,uint16 expectedModels,uint8 outputType)"
const settlementBatchType = "SettlementBatchV5(bytes32 settlementDomain,uint64 validatorSetId,uint64 batchNonce,bytes32 initializationsHash,bytes32 chunksHash,bytes32 requestersHash,bytes32 servicerOwnersHash,bytes32 servicerPayoutsHash)"

type certifiedSettlementExecution struct {
	ExecutionID           string `json:"executionID"`
	Model                 string `json:"model"`
	ServicerOwner         string `json:"servicerOwner"`
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
	Initialize       bool                           `json:"initialize"`
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

type settlementCandidateRequest struct {
	request      certifiedSettlementRequest
	executionIDs []string
}

type preparedSettlementCandidate struct {
	candidate      *AuxiliaryCandidate
	certificateKey []byte
}

// repairOverlappingSettlementCertificates is a bounded compatibility repair
// for certificates produced before per-request serialization. If part of one
// certificate is already settled, its remaining executions cannot be relayed
// without replaying exactly-once results. Requeue only that mixed request so a
// fresh certificate can cover its still-unsettled suffix.
func (c *Contract) repairOverlappingSettlementCertificates(records map[string]proto.Message, deletes *[][]byte) *PluginError {
	next := new(ReplayMarker)
	if found, err := c.read(KeyForSettlementRepairCursorNext(), next); err != nil {
		return err
	} else if !found {
		next.Id = nil
	}
	current := &ReplayMarker{Id: append([]byte(nil), next.Id...)}
	const repairPageSize = uint64(8)
	entries, err := c.rangeReadPage(CertifiedSettlementIndexPrefix(), current.Id, repairPageSize)
	if err != nil {
		return err
	}
	following := &ReplayMarker{}
	if uint64(len(entries)) == repairPageSize {
		following.Id = append([]byte(nil), entries[len(entries)-1].Key...)
	}
	records[string(KeyForSettlementRepairCursorCurrent())] = current
	records[string(KeyForSettlementRepairCursorNext())] = following
	prefix := CertifiedSettlementIndexPrefix()
	for _, entry := range entries {
		requestID, valid := trailingKeySegment(entry.Key, prefix)
		marker := new(ReplayMarker)
		if !valid || Unmarshal(entry.Value, marker) != nil || len(marker.Id) == 0 {
			continue
		}
		certificates, readErr := c.rangeReadPage(ConsensusCertificateIdentityPrefix("settlement", marker.Id), nil, 8)
		if readErr != nil {
			return readErr
		}
		var latest *ConsensusCertificate
		for _, certificateEntry := range certificates {
			certificate := new(ConsensusCertificate)
			if Unmarshal(certificateEntry.Value, certificate) == nil && (latest == nil || certificate.CompletedHeight > latest.CompletedHeight) {
				latest = certificate
			}
		}
		if latest == nil {
			continue
		}
		batch := new(certifiedSettlementBatch)
		if json.Unmarshal(latest.Payload, batch) != nil {
			continue
		}
		var certified *certifiedSettlementRequest
		for index := range batch.Requests {
			if batch.Requests[index].RequestID == string(requestID) {
				certified = &batch.Requests[index]
				break
			}
		}
		if certified == nil {
			continue
		}
		settled, unsettled := 0, 0
		for _, item := range certified.Executions {
			execution := new(ExecutionRecord)
			if found, executionErr := c.read(KeyForExecution(item.ExecutionID), execution); executionErr != nil {
				return executionErr
			} else if !found {
				continue
			} else if execution.Settled {
				settled++
			} else {
				unsettled++
			}
		}
		if settled == 0 || unsettled == 0 {
			continue
		}
		records[string(KeyForUncertifiedSettlementIndex(string(requestID)))] = &RequestRecord{RequestId: string(requestID)}
		*deletes = append(*deletes, KeyForCertifiedSettlementIndex(string(requestID)))
	}
	return nil
}

func trailingKeySegment(key, prefix []byte) ([]byte, bool) {
	if !bytes.HasPrefix(key, prefix) || len(key) <= len(prefix) {
		return nil, false
	}
	tail := key[len(prefix):]
	length := int(tail[0])
	if length == 0 || len(tail) != length+1 {
		return nil, false
	}
	return append([]byte(nil), tail[1:]...), true
}

func (c *Contract) settlementAuxiliaryCandidates(clock *EpochClock, limit int) ([]*AuxiliaryCandidate, *PluginError) {
	if limit <= 0 {
		return nil, nil
	}
	if limit > maxSettlementCertificatesPerBlock {
		limit = maxSettlementCertificatesPerBlock
	}
	cursor := new(ReplayMarker)
	if found, err := c.read(KeyForSettlementCandidateCursorCurrent(), cursor); err != nil {
		return nil, err
	} else if !found {
		cursor.Id = nil
	}
	entries, err := c.rangeReadPage(UncertifiedSettlementIndexPrefix(), cursor.Id, settlementCandidatePageSize)
	if err != nil {
		return nil, err
	}
	requestFactories := make(map[string]stateRecordFactory, len(entries))
	for _, entry := range entries {
		pointer := new(RequestRecord)
		if Unmarshal(entry.Value, pointer) == nil && pointer.RequestId != "" {
			requestFactories[string(KeyForRequest(pointer.RequestId))] = func() proto.Message { return new(RequestRecord) }
		}
	}
	requests, err := c.prefetchStateRecords(requestFactories)
	if err != nil {
		return nil, err
	}
	dependentFactories := make(map[string]stateRecordFactory, len(requests)*3)
	for _, record := range requests {
		request, ok := record.(*RequestRecord)
		if !ok || request == nil || request.RequestId == "" {
			continue
		}
		dependentFactories[string(KeyForReservation(request.SettlementDomainId, request.RequestId))] = func() proto.Message { return new(ReservationRecord) }
		dependentFactories[string(KeyForCertifiedSettlementIndex(request.RequestId))] = func() proto.Message { return new(ReplayMarker) }
		for _, assignment := range request.Assignments {
			if assignment != nil && assignment.Completed && assignment.ExecutionId != "" {
				dependentFactories[string(KeyForExecution(assignment.ExecutionId))] = func() proto.Message { return new(ExecutionRecord) }
			}
		}
	}
	dependents, err := c.prefetchStateRecords(dependentFactories)
	if err != nil {
		return nil, err
	}
	servicerFactories := make(map[string]stateRecordFactory)
	for _, record := range dependents {
		execution, ok := record.(*ExecutionRecord)
		if ok && execution != nil && len(execution.ServicerAddress) != 0 {
			servicerFactories[string(KeyForServicer(execution.ServicerAddress))] = func() proto.Message { return new(Servicer) }
		}
	}
	servicers, err := c.prefetchStateRecords(servicerFactories)
	if err != nil {
		return nil, err
	}
	eligible := make([]settlementCandidateRequest, 0, len(entries))
	for _, entry := range entries {
		pointer := new(RequestRecord)
		if Unmarshal(entry.Value, pointer) != nil || pointer.RequestId == "" {
			continue
		}
		request, found := requests[string(KeyForRequest(pointer.RequestId))].(*RequestRecord)
		if !found || request == nil || request.Status != "authorized" && request.Status != "ready" || len(request.SettlementDomainId) != 32 || len(request.Requester) != 20 || len(request.InputHash) != 32 {
			continue
		}
		reservation, found := dependents[string(KeyForReservation(request.SettlementDomainId, request.RequestId))].(*ReservationRecord)
		if !found || reservation == nil || reservation.Status != "reserved" {
			continue
		}
		// Serialize incremental certificates for one request. A later execution
		// may become terminal while the prior EVM transaction is still pending;
		// certifying both generations would make the second payload overlap the
		// first and become unusable after exactly-once settlement filters it.
		if dependents[string(KeyForCertifiedSettlementIndex(request.RequestId))] != nil {
			continue
		}
		candidate := certifiedSettlementRequest{
			SettlementDomain: "0x" + hex.EncodeToString(request.SettlementDomainId), RequestID: request.RequestId,
			InputHash: "0x" + hex.EncodeToString(request.InputHash), Models: append([]string(nil), request.Models...),
			OutputType: request.OutputType, OutputSchema: certifiedSettlementSchema{Minimum: request.OutputMinimum, Maximum: request.OutputMaximum, Choices: append([]string(nil), request.OutputChoices...)},
			Deadline: request.DeadlineHeight, Requester: "0x" + hex.EncodeToString(request.Requester), ReservedBudget: reservation.Budget, RequestSpent: reservation.Spent,
			Initialize: true, FinalizesRequest: request.Status == "ready",
		}
		var executionIDs []string
		for _, assignment := range request.Assignments {
			if assignment == nil || !assignment.Completed || assignment.ExecutionId == "" {
				continue
			}
			execution, found := dependents[string(KeyForExecution(assignment.ExecutionId))].(*ExecutionRecord)
			if found && execution != nil && execution.Settled {
				candidate.Initialize = false
			}
			if !found || execution == nil || execution.Settled || execution.RequestId != request.RequestId || execution.Model != assignment.Model {
				continue
			}
			servicer, found := servicers[string(KeyForServicer(execution.ServicerAddress))].(*Servicer)
			if !found || servicer == nil {
				continue
			}
			payout := settlementPayout(servicer, request.SettlementDomainId)
			if len(payout) != 20 || execution.Cost > uint64(^uint64(0)>>1) || execution.ProviderCost > uint64(^uint64(0)>>1) || execution.ServicerMargin > uint64(^uint64(0)>>1) || execution.FoundationFee > uint64(^uint64(0)>>1) || ^uint64(0)-execution.ProviderCost < execution.ServicerMargin {
				continue
			}
			candidate.Executions = append(candidate.Executions, certifiedSettlementExecution{
				ExecutionID: execution.ExecutionId, Model: execution.Model,
				ServicerOwner: "0x" + hex.EncodeToString(execution.ServicerAddress), Servicer: "0x" + hex.EncodeToString(payout),
				Output: execution.Output, OutputType: request.OutputType, Status: execution.Status,
				CostMicros: int64(execution.Cost), ServicerPaymentMicros: int64(execution.ProviderCost + execution.ServicerMargin),
				FoundationFeeMicros: int64(execution.FoundationFee), FoundationFeeBps: request.FoundationFeeBps,
			})
			executionIDs = append(executionIDs, execution.ExecutionId)
		}
		if len(candidate.Executions) == 0 {
			continue
		}
		eligible = append(eligible, settlementCandidateRequest{request: candidate, executionIDs: executionIDs})
	}

	groups := make([][]settlementCandidateRequest, 0, len(eligible)/maxSettlementRequestsPerCertificate+1)
	groupExecutionCounts := make([]int, 0, cap(groups))
	openByDomain := make(map[string]int)
	for _, candidate := range eligible {
		domain := candidate.request.SettlementDomain
		groupIndex, found := openByDomain[domain]
		if !found || len(groups[groupIndex]) == maxSettlementRequestsPerCertificate ||
			groupExecutionCounts[groupIndex]+len(candidate.request.Executions) > maxSettlementExecutionsPerCertificate {
			groupIndex = len(groups)
			groups = append(groups, nil)
			groupExecutionCounts = append(groupExecutionCounts, 0)
			openByDomain[domain] = groupIndex
		}
		groups[groupIndex] = append(groups[groupIndex], candidate)
		groupExecutionCounts[groupIndex] += len(candidate.request.Executions)
	}

	prepared := make([]preparedSettlementCandidate, 0, len(groups))
	certificateFactories := make(map[string]stateRecordFactory, len(groups))
	for _, group := range groups {
		requests := make([]certifiedSettlementRequest, len(group))
		identityParts := make([][]byte, 1, 1+3*len(group))
		identityParts[0] = []byte("takusen:settlement-batch:v4")
		for index := range group {
			requests[index] = group[index].request
			identityParts = append(identityParts, []byte(group[index].request.RequestID), stringListBytes(group[index].executionIDs), boolBytes(group[index].request.Initialize))
		}
		identityKey := hashFields(identityParts...)
		batchNonce := binary.BigEndian.Uint64(identityKey[:8])
		if batchNonce == 0 {
			batchNonce = 1
		}
		key := uint64Bytes(batchNonce)
		digest, digestErr := settlementAuthorizationDigest(clock.ValidatorSetId, batchNonce, requests)
		if digestErr != nil {
			continue
		}
		payload, marshalErr := json.Marshal(certifiedSettlementBatch{ValidatorSetID: clock.ValidatorSetId, BatchNonce: batchNonce, Digest: "0x" + hex.EncodeToString(digest), Requests: requests})
		if marshalErr != nil || len(payload) > 64<<10 {
			continue
		}
		certificateKey := KeyForConsensusCertificate("settlement", key, digest)
		certificateFactories[string(certificateKey)] = func() proto.Message { return new(ConsensusCertificate) }
		prepared = append(prepared, preparedSettlementCandidate{
			candidate:      &AuxiliaryCandidate{Kind: "settlement", Key: key, Digest: digest, Payload: payload},
			certificateKey: certificateKey,
		})
	}
	certificates, readErr := c.prefetchStateRecords(certificateFactories)
	if readErr != nil {
		return nil, readErr
	}
	result := make([]*AuxiliaryCandidate, 0, len(prepared))
	for _, item := range prepared {
		if certificates[string(item.certificateKey)] == nil {
			result = append(result, item.candidate)
			if len(result) == limit {
				break
			}
		}
	}
	return result, nil
}

func settlementPayout(servicer *Servicer, _ []byte) []byte {
	return servicer.EvmPayoutAddress
}

func settlementAuthorizationDigest(validatorSetID, batchNonce uint64, requests []certifiedSettlementRequest) ([]byte, error) {
	if len(requests) == 0 {
		return nil, ErrInvalidTransaction("empty settlement batch")
	}
	domain := mustHex(requests[0].SettlementDomain, 32)
	if len(domain) != 32 {
		return nil, ErrInvalidTransaction("invalid settlement domain")
	}
	type preparedRequest struct {
		request      certifiedSettlementRequest
		requestID    [32]byte
		modelIDs     [][]byte
		modelSetHash []byte
	}
	prepared := make([]preparedRequest, 0, len(requests))
	requesterSet := make(map[string][]byte)
	servicerPayouts := make(map[string][]byte)
	for _, request := range requests {
		if !bytes.Equal(domain, mustHex(request.SettlementDomain, 32)) {
			return nil, ErrInvalidTransaction("mixed settlement domains")
		}
		modelIDs := make([][]byte, len(request.Models))
		modelArray := append(abiUint64(32), abiUint64(uint64(len(request.Models)))...)
		for index, model := range request.Models {
			digest := sha256.Sum256([]byte(model))
			modelIDs[index] = digest[:]
			modelArray = append(modelArray, digest[:]...)
		}
		modelSetHash := keccak256(modelArray)
		requestID := sha256.Sum256([]byte(request.RequestID))
		requester := mustHex(request.Requester, 20)
		if len(requester) != 20 {
			return nil, ErrInvalidTransaction("invalid requester")
		}
		requesterSet[string(requester)] = requester
		for _, execution := range request.Executions {
			owner := mustHex(execution.ServicerOwner, 20)
			servicer := mustHex(execution.Servicer, 20)
			if len(owner) != 20 || len(servicer) != 20 {
				return nil, ErrInvalidTransaction("invalid servicer")
			}
			if prior, exists := servicerPayouts[string(owner)]; exists && !bytes.Equal(prior, servicer) {
				return nil, ErrInvalidTransaction("inconsistent servicer payout")
			}
			servicerPayouts[string(owner)] = servicer
		}
		prepared = append(prepared, preparedRequest{request: request, requestID: requestID, modelIDs: modelIDs, modelSetHash: modelSetHash})
	}
	sort.Slice(prepared, func(i, j int) bool { return bytes.Compare(prepared[i].requestID[:], prepared[j].requestID[:]) < 0 })
	requesters := sortedSettlementAddresses(requesterSet)
	servicerOwnerSet := make(map[string][]byte, len(servicerPayouts))
	for owner := range servicerPayouts {
		servicerOwnerSet[owner] = []byte(owner)
	}
	servicerOwners := sortedSettlementAddresses(servicerOwnerSet)
	servicers := make([][]byte, len(servicerOwners))
	for index, owner := range servicerOwners {
		servicers[index] = servicerPayouts[string(owner)]
	}
	requesterIndices := settlementAddressIndices(requesters)
	servicerIndices := settlementAddressIndices(servicerOwners)
	initializationHashes := make([]byte, 0)
	chunkHashes := make([]byte, 0)
	for _, preparedRequest := range prepared {
		request := preparedRequest.request
		requestID := preparedRequest.requestID
		modelSetHash := preparedRequest.modelSetHash
		requester := mustHex(request.Requester, 20)
		requestOutputType, outputTypeOK := settlementOutputTypeCode(request.OutputType)
		if !outputTypeOK {
			return nil, ErrInvalidTransaction("invalid request output type")
		}
		if request.Initialize {
			encoded := append([]byte{}, keccak256([]byte(requestInitializationType))...)
			encoded = append(encoded, requestID[:]...)
			encoded = append(encoded, mustHex(request.InputHash, 32)...)
			encoded = append(encoded, modelSetHash...)
			encoded = append(encoded, requestSchemaHash(request)...)
			encoded = append(encoded, abiAddress(requester)...)
			encoded = append(encoded, abiUint64(request.ReservedBudget)...)
			encoded = append(encoded, abiUint64(request.Deadline)...)
			encoded = append(encoded, abiUint64(requestOutputType)...)
			encoded = append(encoded, modelSetHash...)
			initializationHashes = append(initializationHashes, keccak256(encoded)...)
		}
		commitment := append([]byte{}, keccak256([]byte(requestCommitmentType))...)
		commitment = append(commitment, requestID[:]...)
		commitment = append(commitment, mustHex(request.InputHash, 32)...)
		commitment = append(commitment, modelSetHash...)
		commitment = append(commitment, requestSchemaHash(request)...)
		commitment = append(commitment, abiAddress(requester)...)
		commitment = append(commitment, abiUint64(request.ReservedBudget)...)
		commitment = append(commitment, abiUint64(request.Deadline)...)
		commitment = append(commitment, abiUint64(uint64(len(request.Models)))...)
		commitment = append(commitment, abiUint64(requestOutputType)...)
		requestCommitment := keccak256(commitment)

		type packedResult struct {
			ordinal uint8
			data    []byte
		}
		modelOrdinals := make(map[string]uint8, len(request.Models))
		for index, model := range request.Models {
			modelOrdinals[model] = uint8(index)
		}
		packedItems := make([]packedResult, 0, len(request.Executions))
		for _, execution := range request.Executions {
			outputType, output, ok := settlementOutput(request, execution)
			if !ok || outputType != requestOutputType {
				return nil, ErrInvalidTransaction("invalid settlement output")
			}
			status := uint64(1)
			switch execution.Status {
			case "success":
			case "budget_exhausted", "non_answer":
				status = 2
			case "timeout":
				status = 3
			default:
				return nil, ErrInvalidTransaction("invalid settlement status")
			}
			ordinal, committed := modelOrdinals[execution.Model]
			servicer := mustHex(execution.ServicerOwner, 20)
			if !committed || execution.CostMicros < 0 || execution.CostMicros > 100_000_000 ||
				execution.FoundationFeeMicros < 0 || execution.FoundationFeeMicros > int64(^uint32(0)) ||
				execution.ServicerPaymentMicros < 0 || execution.ServicerPaymentMicros+execution.FoundationFeeMicros != execution.CostMicros ||
				execution.ExecutionID != settlementExecutionID(domain, requestID, sha256.Sum256([]byte(execution.Model)), servicer, mustHex(request.InputHash, 32)) {
				return nil, ErrInvalidTransaction("invalid derivable settlement execution")
			}
			recordSize := 13
			if outputType == 4 {
				recordSize = 44
			}
			record := make([]byte, recordSize)
			record[0] = ordinal
			binary.BigEndian.PutUint16(record[1:3], servicerIndices[string(servicer)])
			binary.BigEndian.PutUint32(record[3:7], uint32(execution.CostMicros))
			binary.BigEndian.PutUint32(record[7:11], uint32(execution.FoundationFeeMicros))
			record[11] = byte(status)
			if outputType == 4 {
				copy(record[12:], output)
			} else {
				record[12] = output[31]
			}
			packedItems = append(packedItems, packedResult{ordinal: ordinal, data: record})
		}
		sort.Slice(packedItems, func(i, j int) bool { return packedItems[i].ordinal < packedItems[j].ordinal })
		packedResults := make([]byte, 0, 13*len(packedItems))
		for _, item := range packedItems {
			packedResults = append(packedResults, item.data...)
		}
		chunk := append([]byte{}, keccak256([]byte(requestChunkType))...)
		chunk = append(chunk, requestID[:]...)
		chunk = append(chunk, requestCommitment...)
		chunk = append(chunk, abiUint64(request.RequestSpent)...)
		chunk = append(chunk, abiUint64(uint64(requesterIndices[string(requester)]))...)
		chunk = append(chunk, keccak256(packedResults)...)
		chunkHashes = append(chunkHashes, keccak256(chunk)...)
	}
	encoded := append([]byte{}, keccak256([]byte(settlementBatchType))...)
	encoded = append(encoded, domain...)
	encoded = append(encoded, abiUint64(validatorSetID)...)
	encoded = append(encoded, abiUint64(batchNonce)...)
	encoded = append(encoded, keccak256(initializationHashes)...)
	encoded = append(encoded, keccak256(chunkHashes)...)
	encoded = append(encoded, keccak256(abiAddressArray(requesters))...)
	encoded = append(encoded, keccak256(abiAddressArray(servicerOwners))...)
	encoded = append(encoded, keccak256(abiAddressArray(servicers))...)
	return keccak256(encoded), nil
}

func sortedSettlementAddresses(set map[string][]byte) [][]byte {
	result := make([][]byte, 0, len(set))
	for _, address := range set {
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return bytes.Compare(result[i], result[j]) < 0 })
	return result
}

func settlementAddressIndices(addresses [][]byte) map[string]uint16 {
	result := make(map[string]uint16, len(addresses))
	for index, address := range addresses {
		result[string(address)] = uint16(index)
	}
	return result
}

func settlementExecutionID(domain []byte, requestID [32]byte, modelID [32]byte, servicer, inputHash []byte) string {
	if len(domain) != 32 || len(servicer) != 20 || len(inputHash) != 32 {
		return ""
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("takusen:execution:v5"))
	_, _ = hash.Write(domain)
	_, _ = hash.Write(requestID[:])
	_, _ = hash.Write(modelID[:])
	_, _ = hash.Write(servicer)
	_, _ = hash.Write(inputHash)
	return "exec:" + hex.EncodeToString(hash.Sum(nil))
}

func settlementOutputTypeCode(outputType string) (uint64, bool) {
	switch outputType {
	case "boolean":
		return 1, true
	case "score":
		return 2, true
	case "choice":
		return 3, true
	case "private_hash":
		return 4, true
	default:
		return 0, false
	}
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
