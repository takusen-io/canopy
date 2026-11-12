package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"sort"
	"strconv"

	"google.golang.org/protobuf/proto"
)

func (c *Contract) deliverQueueAuthorization(height uint64, message *MessageQueueAuthorization) *PluginDeliverResponse {
	authorization := proto.Clone(message.Authorization).(*MessageObserveAuthorization)
	authorization.ObserverAddress = nil
	if found, err := c.read(KeyForRequest(authorization.RequestId), new(RequestRecord)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{}
	}
	key := KeyForPendingAuthorization(authorization.RequestId)
	existing := new(PendingAuthorization)
	if found, err := c.read(key, existing); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		encoded, marshalErr := Marshal(authorization)
		if marshalErr != nil {
			return &PluginDeliverResponse{Error: marshalErr}
		}
		if !bytes.Equal(existing.Authorization, encoded) {
			return &PluginDeliverResponse{Error: ErrConflict("request authorization intent already exists with different fields")}
		}
		return &PluginDeliverResponse{}
	}
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if !authorizationWindowValid(height, authorization.AuthorizationDeadline, params.AuthorizationDeadlineBlocks) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("request authorization has expired or exceeds the governed limit")}
	}
	encoded, err := Marshal(authorization)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{string(key): &PendingAuthorization{
		RequestId: authorization.RequestId, SettlementDomainId: append([]byte(nil), authorization.SettlementDomainId...),
		Authorization: encoded, QueuedHeight: height,
	}})}
}

func (c *Contract) expiredPendingAuthorizations(height uint64, limit uint64) ([][]byte, *PluginError) {
	entries, err := c.rangeReadPage(PendingAuthorizationPrefix(), nil, limit)
	if err != nil {
		return nil, err
	}
	deletes := make([][]byte, 0)
	for _, entry := range entries {
		pending := new(PendingAuthorization)
		if Unmarshal(entry.Value, pending) != nil {
			continue
		}
		authorization := new(MessageObserveAuthorization)
		if Unmarshal(pending.Authorization, authorization) != nil {
			continue
		}
		found, readErr := c.read(KeyForRequest(pending.RequestId), new(RequestRecord))
		if readErr != nil {
			return nil, readErr
		}
		if found || authorization.AuthorizationDeadline <= height || authorization.DeadlineHeight <= height {
			deletes = append(deletes, append([]byte(nil), entry.Key...))
		}
	}
	return deletes, nil
}

func (c *Contract) deliverObserveAuthorization(height uint64, message *MessageObserveAuthorization) *PluginDeliverResponse {
	return c.deliverObserveAuthorizationCertified(height, message, false)
}

func (c *Contract) deliverObserveAuthorizationCertified(height uint64, message *MessageObserveAuthorization, certified bool) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if !outputSchemaEnabled(params, message.OutputType) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("request output schema is not governed")}
	}
	if len(params.Models) != 0 {
		for _, model := range message.Models {
			if modelPolicy(params, model) == nil {
				return &PluginDeliverResponse{Error: ErrUnauthorized("request model is not active")}
			}
		}
	}
	if params.AuthorizationDeadlineBlocks != 0 &&
		(message.DeadlineHeight <= height || message.DeadlineHeight-height > params.AuthorizationDeadlineBlocks) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("request deadline exceeds the governed limit")}
	}
	if !authorizationWindowValid(height, message.AuthorizationDeadline, params.AuthorizationDeadlineBlocks) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("request authorization has expired or exceeds the governed limit")}
	}
	if message.DirectEoa {
		if message.AuthorizationChainBlockNumber != 0 || len(message.AuthorizationChainBlockHash) != 0 {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("EOA authorization must not carry settlement-chain state evidence")}
		}
	} else if message.AuthorizationChainBlockNumber == 0 || len(message.AuthorizationChainBlockHash) != 32 {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("ERC-1271 authorization requires canonical settlement-chain state evidence")}
	}
	if found, err := c.read(KeyForRequest(message.RequestId), new(RequestRecord)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("request is already authorized")}
	}
	subject := authorizationSubject(message)
	claim := hashFields([]byte("authorization"), []byte(message.RequestId))
	reached := false
	records := make(map[string]proto.Message)
	if message.DirectEoa {
		if verifyErr := verifyEOARequestAuthorization(message, params); verifyErr != nil {
			return &PluginDeliverResponse{Error: verifyErr}
		}
		reached = true
	} else if certified {
		reached = true
	} else {
		observation, observed, observeErr := c.observe(observationAuthorization, subject, claim, message.ObserverAddress, height)
		if observeErr != nil {
			return &PluginDeliverResponse{Error: observeErr}
		}
		reached = observed
		records = observationRecords(observationAuthorization, subject, claim, message.ObserverAddress, observation)
	}
	if reached {
		if found, readErr := c.read(KeyForReservation(message.SettlementDomainId, message.RequestId), new(ReservationRecord)); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found {
			return &PluginDeliverResponse{Error: ErrConflict("request budget is already reserved")}
		}
		credit := new(CreditAccount)
		if found, readErr := c.read(KeyForCredit(message.SettlementDomainId, message.Requester), credit); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found {
			return &PluginDeliverResponse{Error: ErrState("requester has no witnessed settlement-domain deposits")}
		}
		finalAvailable, valid := safeAvailableCredit(credit)
		if !valid || !bytes.Equal(credit.Requester, message.Requester) || !bytes.Equal(credit.SettlementDomainId, message.SettlementDomainId) {
			return &PluginDeliverResponse{Error: ErrState("requester credit account invariant failed")}
		}
		if finalAvailable < message.ReservedBudget || ^uint64(0)-credit.Reserved < message.ReservedBudget {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("insufficient safe settlement-domain credits")}
		}
		provisionalBudget := uint64(0)
		if message.DeadlineHeight <= height {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("request deadline has already elapsed")}
		}
		anchor := new(BlockAnchor)
		if found, readErr := c.read(KeyForBlockAnchor(), anchor); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || anchor.Height != height || len(anchor.PreviousBlockHash) == 0 {
			return &PluginDeliverResponse{Error: ErrState("current finalized-block assignment anchor is unavailable")}
		}
		assignments := make([]*Assignment, 0, len(message.Models))
		for modelIndex, model := range message.Models {
			policy := modelPolicy(params, model)
			if policy == nil && len(params.Models) != 0 {
				return &PluginDeliverResponse{Error: ErrUnauthorized("request model is not active")}
			}
			provider := "provider"
			if policy != nil {
				provider = policy.Provider
			}
			servicers, selectErr := c.eligibleServicers(model)
			if selectErr != nil {
				return &PluginDeliverResponse{Error: selectErr}
			}
			if len(servicers) == 0 {
				return &PluginDeliverResponse{Error: ErrState("no bonded servicer supports model " + model)}
			}
			selected := selectServicer(message.InputHash, anchor.PreviousBlockHash, model, 0, servicers)
			maximumProviderCost, costErr := assignmentMaxProviderCost(message.ReservedBudget, modelIndex, len(message.Models), params.ServicerMarginBps, params.FoundationFeeBps)
			if costErr != nil {
				return &PluginDeliverResponse{Error: costErr}
			}
			assignments = append(assignments, &Assignment{
				Model: model, ServicerAddress: selected.OwnerAddress, DeadlineHeight: message.DeadlineHeight,
				ExecutionId: assignmentExecutionID(message.RequestId, model, 0, selected.OwnerAddress, message.InputHash),
				TeeKeyId:    selected.TeeKeyId, Provider: provider, MaxProviderCost: maximumProviderCost,
			})
		}
		request := &RequestRecord{
			RequestId: message.RequestId, InputHash: message.InputHash, Requester: message.Requester,
			SettlementDomainId: append([]byte(nil), message.SettlementDomainId...),
			RequestArchiveId:   message.RequestArchiveId,
			OutputType:         message.OutputType, Models: append([]string(nil), message.Models...),
			OutputMinimum: message.OutputMinimum, OutputMaximum: message.OutputMaximum,
			OutputChoices: append([]string(nil), message.OutputChoices...), SchemaHash: append([]byte(nil), message.SchemaHash...),
			ExecutionQuorum: message.ExecutionQuorum, DeadlineHeight: message.DeadlineHeight,
			AuthorizedHeight: height, AssignmentSeed: anchor.PreviousBlockHash, Assignments: assignments, Status: "authorized",
			ParameterRevision: params.Revision, FoundationFeeBps: params.FoundationFeeBps,
			ServicerMarginBps:          params.ServicerMarginBps,
			AuthorizationSignatureHash: hashFields(message.AuthorizationSignature),
		}
		records[string(KeyForRequest(message.RequestId))] = request
		stageAssignmentIndexes(records, request, nil)
		credit.Reserved += message.ReservedBudget
		credit.ProvisionalReserved += provisionalBudget
		records[string(KeyForCredit(message.SettlementDomainId, message.Requester))] = credit
		records[string(KeyForReservation(message.SettlementDomainId, message.RequestId))] = &ReservationRecord{
			RequestId: message.RequestId, Requester: append([]byte(nil), message.Requester...), Budget: message.ReservedBudget,
			SettlementDomainId: append([]byte(nil), message.SettlementDomainId...),
			Status:             "reserved", ReservedHeight: height, AuthorizationDeadline: message.AuthorizationDeadline,
			ProvisionalBudget: provisionalBudget,
		}
		if provisionalBudget != 0 {
			records[string(KeyForProvisionalReservation(message.SettlementDomainId, message.Requester, message.RequestId))] = &ReplayMarker{Id: []byte(message.RequestId)}
		}
	}
	if certified && reached {
		return &PluginDeliverResponse{Error: c.writeChanges(records, [][]byte{KeyForPendingAuthorization(message.RequestId)})}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) deliverObserveAuthorizations(height uint64, message *MessageObserveAuthorizations) *PluginDeliverResponse {
	direct := len(message.Authorizations) != 0
	for _, authorization := range message.Authorizations {
		if authorization == nil || !authorization.DirectEoa || !bytes.Equal(authorization.ObserverAddress, message.ObserverAddress) {
			direct = false
			break
		}
	}
	if direct {
		return c.deliverDirectAuthorizations(height, message)
	}
	for _, authorization := range message.Authorizations {
		if response := c.deliverObserveAuthorization(height, authorization); response.Error != nil {
			return response
		}
	}
	return &PluginDeliverResponse{}
}

// deliverDirectAuthorizations preserves the exact single-request validation
// rules while sharing immutable state reads and committing the cohort in one
// plugin write. The former loop reloaded parameters, the complete servicer
// roster, every enclave, and the same requester credit for every item, then
// crossed the plugin IPC boundary once per authorization.
func (c *Contract) deliverDirectAuthorizations(height uint64, message *MessageObserveAuthorizations) *PluginDeliverResponse {
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if verifyErr := verifyEOARequestAuthorizations(message.Authorizations, params); verifyErr != nil {
		return &PluginDeliverResponse{Error: verifyErr}
	}
	anchor := new(BlockAnchor)
	if found, readErr := c.read(KeyForBlockAnchor(), anchor); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || anchor.Height != height || len(anchor.PreviousBlockHash) == 0 {
		return &PluginDeliverResponse{Error: ErrState("current finalized-block assignment anchor is unavailable")}
	}
	records := make(map[string]proto.Message, len(message.Authorizations)*4+1)
	factories := make(map[string]stateRecordFactory, len(message.Authorizations)*2+1)
	for _, authorization := range message.Authorizations {
		factories[string(KeyForRequest(authorization.RequestId))] = func() proto.Message { return new(RequestRecord) }
		factories[string(KeyForReservation(authorization.SettlementDomainId, authorization.RequestId))] = func() proto.Message { return new(ReservationRecord) }
		factories[string(KeyForCredit(authorization.SettlementDomainId, authorization.Requester))] = func() proto.Message { return new(CreditAccount) }
	}
	loaded, loadErr := c.prefetchStateRecords(factories)
	if loadErr != nil {
		return &PluginDeliverResponse{Error: loadErr}
	}
	eligible := make(map[string][]*Servicer)
	for _, authorization := range message.Authorizations {
		if response := c.stageDirectAuthorization(height, authorization, params, anchor, eligible, records, loaded); response != nil {
			return response
		}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) stageDirectAuthorization(height uint64, message *MessageObserveAuthorization, params *ProtocolParams, anchor *BlockAnchor, eligible map[string][]*Servicer, records, loaded map[string]proto.Message) *PluginDeliverResponse {
	if !outputSchemaEnabled(params, message.OutputType) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("request output schema is not governed")}
	}
	if len(params.Models) != 0 {
		for _, model := range message.Models {
			if modelPolicy(params, model) == nil {
				return &PluginDeliverResponse{Error: ErrUnauthorized("request model is not active")}
			}
		}
	}
	if params.AuthorizationDeadlineBlocks != 0 &&
		(message.DeadlineHeight <= height || message.DeadlineHeight-height > params.AuthorizationDeadlineBlocks) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("request deadline exceeds the governed limit")}
	}
	if !authorizationWindowValid(height, message.AuthorizationDeadline, params.AuthorizationDeadlineBlocks) ||
		message.AuthorizationChainBlockNumber != 0 || len(message.AuthorizationChainBlockHash) != 0 {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("direct request authorization expiry or settlement-chain evidence is invalid")}
	}
	if found, readErr := c.readExecutionStaged(records, loaded, KeyForRequest(message.RequestId), new(RequestRecord)); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("request is already authorized")}
	}
	if found, readErr := c.readExecutionStaged(records, loaded, KeyForReservation(message.SettlementDomainId, message.RequestId), new(ReservationRecord)); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("request budget is already reserved")}
	}
	credit := new(CreditAccount)
	if found, readErr := c.readExecutionStaged(records, loaded, KeyForCredit(message.SettlementDomainId, message.Requester), credit); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found {
		return &PluginDeliverResponse{Error: ErrState("requester has no witnessed settlement-domain deposits")}
	}
	finalAvailable, valid := safeAvailableCredit(credit)
	if !valid || !bytes.Equal(credit.Requester, message.Requester) || !bytes.Equal(credit.SettlementDomainId, message.SettlementDomainId) {
		return &PluginDeliverResponse{Error: ErrState("requester credit account invariant failed")}
	}
	if finalAvailable < message.ReservedBudget || ^uint64(0)-credit.Reserved < message.ReservedBudget {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("insufficient safe settlement-domain credits")}
	}
	provisionalBudget := uint64(0)
	if message.DeadlineHeight <= height {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("request deadline has already elapsed")}
	}

	assignments := make([]*Assignment, 0, len(message.Models))
	for modelIndex, model := range message.Models {
		policy := modelPolicy(params, model)
		if policy == nil && len(params.Models) != 0 {
			return &PluginDeliverResponse{Error: ErrUnauthorized("request model is not active")}
		}
		provider := "provider"
		if policy != nil {
			provider = policy.Provider
		}
		servicers, loaded := eligible[model]
		if !loaded {
			var selectErr *PluginError
			servicers, selectErr = c.eligibleServicers(model)
			if selectErr != nil {
				return &PluginDeliverResponse{Error: selectErr}
			}
			eligible[model] = servicers
		}
		if len(servicers) == 0 {
			return &PluginDeliverResponse{Error: ErrState("no bonded servicer supports model " + model)}
		}
		selected := selectServicer(message.InputHash, anchor.PreviousBlockHash, model, 0, servicers)
		maximumProviderCost, costErr := assignmentMaxProviderCost(message.ReservedBudget, modelIndex, len(message.Models), params.ServicerMarginBps, params.FoundationFeeBps)
		if costErr != nil {
			return &PluginDeliverResponse{Error: costErr}
		}
		assignments = append(assignments, &Assignment{
			Model: model, ServicerAddress: selected.OwnerAddress, DeadlineHeight: message.DeadlineHeight,
			ExecutionId: assignmentExecutionID(message.RequestId, model, 0, selected.OwnerAddress, message.InputHash),
			TeeKeyId:    selected.TeeKeyId, Provider: provider, MaxProviderCost: maximumProviderCost,
		})
	}
	request := &RequestRecord{
		RequestId: message.RequestId, InputHash: message.InputHash, Requester: message.Requester,
		SettlementDomainId: append([]byte(nil), message.SettlementDomainId...),
		RequestArchiveId:   message.RequestArchiveId,
		OutputType:         message.OutputType, Models: append([]string(nil), message.Models...),
		OutputMinimum: message.OutputMinimum, OutputMaximum: message.OutputMaximum,
		OutputChoices: append([]string(nil), message.OutputChoices...), SchemaHash: append([]byte(nil), message.SchemaHash...),
		ExecutionQuorum: message.ExecutionQuorum, DeadlineHeight: message.DeadlineHeight,
		AuthorizedHeight: height, AssignmentSeed: anchor.PreviousBlockHash, Assignments: assignments, Status: "authorized",
		ParameterRevision: params.Revision, FoundationFeeBps: params.FoundationFeeBps,
		ServicerMarginBps:          params.ServicerMarginBps,
		AuthorizationSignatureHash: hashFields(message.AuthorizationSignature),
	}
	records[string(KeyForRequest(message.RequestId))] = request
	stageAssignmentIndexes(records, request, nil)
	credit.Reserved += message.ReservedBudget
	credit.ProvisionalReserved += provisionalBudget
	records[string(KeyForCredit(message.SettlementDomainId, message.Requester))] = credit
	records[string(KeyForReservation(message.SettlementDomainId, message.RequestId))] = &ReservationRecord{
		RequestId: message.RequestId, Requester: append([]byte(nil), message.Requester...), Budget: message.ReservedBudget,
		SettlementDomainId: append([]byte(nil), message.SettlementDomainId...),
		Status:             "reserved", ReservedHeight: height, AuthorizationDeadline: message.AuthorizationDeadline,
		ProvisionalBudget: provisionalBudget,
	}
	if provisionalBudget != 0 {
		records[string(KeyForProvisionalReservation(message.SettlementDomainId, message.Requester, message.RequestId))] = &ReplayMarker{Id: []byte(message.RequestId)}
	}
	return nil
}

func authorizationWindowValid(height, deadline, maximum uint64) bool {
	return maximum != 0 && deadline > height && deadline-height <= maximum
}

func assignmentMaxProviderCost(reservedBudget uint64, modelIndex, modelCount int, marginBps, feeBps uint32) (uint64, *PluginError) {
	if reservedBudget == 0 || modelCount <= 0 || modelIndex < 0 || modelIndex >= modelCount {
		return 0, ErrInvalidTransaction("assignment model allocation is invalid")
	}
	modelBudget := reservedBudget / uint64(modelCount)
	if uint64(modelIndex) < reservedBudget%uint64(modelCount) {
		modelBudget++
	}
	return maxProviderCost(modelBudget, marginBps, feeBps)
}

func (c *Contract) deliverReassignRequest(height uint64, message *MessageReassignRequest) *PluginDeliverResponse {
	return c.deliverReassignRequestWithCertificate(height, message, false)
}

func (c *Contract) deliverReassignRequestWithCertificate(height uint64, message *MessageReassignRequest, certified bool) *PluginDeliverResponse {
	request := new(RequestRecord)
	if found, err := c.read(KeyForRequest(message.RequestId), request); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || request.Status != "authorized" {
		return &PluginDeliverResponse{Error: ErrNotFound("active request not found")}
	}
	assignment := findAssignment(request, message.Model)
	if assignment == nil || assignment.Completed {
		return &PluginDeliverResponse{Error: ErrConflict("model assignment is absent or already completed")}
	}
	previousAssignments := activeAssignmentOwners(request)
	assignmentDeadline := assignment.DeadlineHeight
	if assignmentDeadline == 0 {
		return &PluginDeliverResponse{Error: ErrState("assignment deadline is missing")}
	}
	if height <= assignmentDeadline || message.NewDeadlineHeight <= height {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("reassignment requires an elapsed assignment deadline and a future replacement deadline")}
	}
	awaitingServicer := assignment.TerminalStatus == "awaiting_servicer"
	nextAttempt := assignment.Attempt + 1
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if params.AuthorizationDeadlineBlocks != 0 && message.NewDeadlineHeight-height > params.AuthorizationDeadlineBlocks {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("replacement assignment deadline exceeds the governed limit")}
	}
	subject := reassignmentSubject(message, nextAttempt)
	claim := hashFields([]byte("reassignment"), []byte(message.RequestId), []byte(message.Model), uint32Bytes(nextAttempt), uint64Bytes(message.NewDeadlineHeight))
	reached := certified
	records := make(map[string]proto.Message)
	if !certified {
		observation, observed, err := c.observe(observationReassignment, subject, claim, message.ObserverAddress, height)
		if err != nil {
			return &PluginDeliverResponse{Error: err}
		}
		reached = observed
		records = observationRecords(observationReassignment, subject, claim, message.ObserverAddress, observation)
	}
	if reached {
		if !awaitingServicer {
			previousAddress := append([]byte(nil), assignment.ServicerAddress...)
			previous := new(Servicer)
			if found, readErr := c.read(KeyForServicer(previousAddress), previous); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if !found || previous.Bond == 0 {
				return &PluginDeliverResponse{Error: ErrState("timed-out assignment references a missing bonded servicer")}
			}
			if previous.FailureCount == ^uint64(0) {
				return &PluginDeliverResponse{Error: ErrState("servicer failure counter overflow")}
			}
			previous.FailureCount++
			records[string(KeyForServicer(previousAddress))] = previous
			if slashErr := c.queueTimeoutSlash(height, request.RequestId, message.Model, nextAttempt, previous, params, records); slashErr != nil {
				return &PluginDeliverResponse{Error: slashErr}
			}
		}

		if nextAttempt > params.RetryLimit {
			if failErr := c.failAssignment(height, request, assignment, records); failErr != nil {
				return &PluginDeliverResponse{Error: failErr}
			}
		} else {
			servicers, selectErr := c.eligibleServicers(message.Model)
			if selectErr != nil {
				return &PluginDeliverResponse{Error: selectErr}
			}
			if len(servicers) == 0 {
				assignment.DeadlineHeight = message.NewDeadlineHeight
				assignment.TerminalStatus = "awaiting_servicer"
				records[string(KeyForRequest(request.RequestId))] = request
				deletes := stageAssignmentIndexes(records, request, previousAssignments)
				return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
			}
			selected := selectServicer(request.InputHash, request.AssignmentSeed, message.Model, nextAttempt, servicers)
			policy := modelPolicy(params, message.Model)
			if policy == nil && len(params.Models) != 0 {
				if failErr := c.failAssignment(height, request, assignment, records); failErr != nil {
					return &PluginDeliverResponse{Error: failErr}
				}
				deletes := stageAssignmentIndexes(records, request, previousAssignments)
				return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
			}
			provider := "provider"
			if policy != nil {
				provider = policy.Provider
			}
			assignment.ServicerAddress = append([]byte(nil), selected.OwnerAddress...)
			assignment.Attempt = nextAttempt
			assignment.DeadlineHeight = message.NewDeadlineHeight
			assignment.ExecutionId = assignmentExecutionID(request.RequestId, message.Model, nextAttempt, selected.OwnerAddress, request.InputHash)
			assignment.TeeKeyId = selected.TeeKeyId
			assignment.Provider = provider
			assignment.TerminalStatus = ""
			records[string(KeyForRequest(request.RequestId))] = request
		}
		deletes := stageAssignmentIndexes(records, request, previousAssignments)
		return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) failAssignment(height uint64, request *RequestRecord, assignment *Assignment, records map[string]proto.Message) *PluginError {
	assignment.Completed = true
	assignment.TerminalStatus = "failed"
	failedHash := sha256.Sum256(nil)
	records[string(KeyForExecution(assignment.ExecutionId))] = &ExecutionRecord{
		ExecutionId: assignment.ExecutionId, RequestId: request.RequestId, Model: assignment.Model,
		Provider: assignment.Provider, ServicerAddress: append([]byte(nil), assignment.ServicerAddress...),
		Status: "failed", OutputHash: failedHash[:], TeeKeyId: assignment.TeeKeyId, CommittedHeight: height,
	}
	if allAssignmentsResolved(request) {
		executions, err := c.collectExecutions(request, nil)
		if err != nil {
			return err
		}
		request.ConsensusOutputHash, request.AgreementCount = agreement(executions)
		request.Status = "ready"
	} else {
		request.Status = "authorized"
	}
	records[string(KeyForRequest(request.RequestId))] = request
	return nil
}

// assignmentExecutionID is consensus-owned assignment identity. The servicer
// host may verify it but never chooses it.
func assignmentExecutionID(requestID, model string, attempt uint32, servicerAddress, inputHash []byte) string {
	material := "takusen:execution:v2\x00" + requestID + "\x00" + model + "\x00" +
		strconv.FormatUint(uint64(attempt), 10) + "\x00" + hex.EncodeToString(servicerAddress) + "\x00" + hex.EncodeToString(inputHash)
	digest := sha256.Sum256([]byte(material))
	return "exec:" + hex.EncodeToString(digest[:])
}

func (c *Contract) queueTimeoutSlash(height uint64, requestID, model string, attempt uint32, servicer *Servicer, params *ProtocolParams, records map[string]proto.Message) *PluginError {
	evidenceID := hashFields([]byte("takusen:timeout"), []byte(requestID), []byte(model), uint32Bytes(attempt))
	if found, err := c.read(KeyForSlashEvidence(evidenceID), new(SlashEvidence)); err != nil {
		return err
	} else if found {
		return ErrState("timeout slash evidence is already committed")
	}
	penalty, valid := mulDiv64(servicer.Bond, uint64(params.TimeoutSlashBps), 10_000)
	if !valid {
		return ErrState("servicer timeout slash calculation overflow")
	}
	if params.TimeoutSlashBps != 0 && penalty == 0 {
		penalty = 1
	}
	clock, err := c.currentEpochClock(params)
	if err != nil {
		return err
	}
	records[string(KeyForSlashEvidence(evidenceID))] = &SlashEvidence{
		EvidenceId: evidenceID, TargetAddress: append([]byte(nil), servicer.OwnerAddress...),
		Reason: "timeout", Penalty: penalty, ObservedHeight: height,
		EffectiveEpoch: clock.CurrentEpoch, Status: "queued",
	}
	records[string(KeyForPendingSlash(clock.CurrentEpoch, evidenceID))] = &ReplayMarker{Id: append([]byte(nil), evidenceID...)}
	return nil
}

func (c *Contract) releaseTimedOutRequest(height uint64, request *RequestRecord, records map[string]proto.Message) *PluginError {
	reservation := new(ReservationRecord)
	if found, err := c.read(KeyForReservation(request.SettlementDomainId, request.RequestId), reservation); err != nil {
		return err
	} else if !found || reservation.Status != "reserved" || reservation.Spent > reservation.Budget ||
		!bytes.Equal(reservation.Requester, request.Requester) {
		return ErrState("timed-out request reservation is unavailable or inconsistent")
	}
	credit := new(CreditAccount)
	if found, err := c.read(KeyForCredit(request.SettlementDomainId, request.Requester), credit); err != nil {
		return err
	} else if !found || !bytes.Equal(credit.Requester, request.Requester) || credit.Reserved < reservation.Budget ||
		credit.ProvisionalReserved < reservation.ProvisionalBudget || ^uint64(0)-credit.Settled < reservation.Spent ||
		^uint64(0)-credit.Released < reservation.Budget-reservation.Spent {
		return ErrState("requester credit account cannot release the timed-out reservation")
	}
	credit.Reserved -= reservation.Budget
	credit.ProvisionalReserved -= reservation.ProvisionalBudget
	credit.Settled += reservation.Spent
	credit.Released += reservation.Budget - reservation.Spent
	if _, valid := availableCredit(credit); !valid {
		return ErrState("requester credit account invariant failed after timeout")
	}
	reservation.Released = reservation.Budget - reservation.Spent
	reservation.Status = "released"
	reservation.ReleasedHeight = height
	request.Status = "timed_out"
	records[string(KeyForRequest(request.RequestId))] = request
	records[string(KeyForReservation(request.SettlementDomainId, request.RequestId))] = reservation
	records[string(KeyForCredit(request.SettlementDomainId, request.Requester))] = credit
	return nil
}

func (c *Contract) deliverFinalizeRequest(height uint64, message *MessageFinalizeRequest) *PluginDeliverResponse {
	records := make(map[string]proto.Message)
	var deletes [][]byte
	if response := c.stageFinalizeRequestCertified(height, message, false, records, nil, &deletes); response.Error != nil {
		return response
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

func (c *Contract) deliverFinalizeRequests(height uint64, message *MessageFinalizeRequests) *PluginDeliverResponse {
	if err := c.verifyValidatorCertificate(settlementBatchSubject(message.Requests), message.ValidatorSetId, message.SignerBitmap, message.AggregateSignature); err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	return c.deliverFinalizeRequestsConsensus(height, message)
}

// deliverFinalizeRequestsConsensus applies an EVM fact already certified by
// the Native auxiliary-certificate path. Its aggregate signs the
// domain/block-bound observation envelope, so it must not be reinterpreted as
// the legacy settlement-subject certificate checked above.
func (c *Contract) deliverFinalizeRequestsConsensus(height uint64, message *MessageFinalizeRequests) *PluginDeliverResponse {
	loaded, loadErr := c.prefetchFinalizationState(message.Requests)
	if loadErr != nil {
		return &PluginDeliverResponse{Error: loadErr}
	}
	records := make(map[string]proto.Message, len(message.Requests)*4)
	deletes := make([][]byte, 0, len(message.Requests))
	for _, request := range message.Requests {
		if response := c.stageFinalizeRequestCertified(height, request, true, records, loaded, &deletes); response.Error != nil {
			return response
		}
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

func (c *Contract) prefetchFinalizationState(messages []*MessageFinalizeRequest) (map[string]proto.Message, *PluginError) {
	factories := make(map[string]stateRecordFactory, len(messages)*4)
	for _, message := range messages {
		factories[string(KeyForRequest(message.RequestId))] = func() proto.Message { return new(RequestRecord) }
		factories[string(KeyForReservation(message.SettlementDomainId, message.RequestId))] = func() proto.Message { return new(ReservationRecord) }
		for _, executionID := range message.ExecutionIds {
			factories[string(KeyForExecution(executionID))] = func() proto.Message { return new(ExecutionRecord) }
		}
	}
	loaded, err := c.prefetchStateRecords(factories)
	if err != nil {
		return nil, err
	}
	// Request records identify any additional assignment executions and the
	// shared credit accounts needed by the staged batch.
	additional := make(map[string]stateRecordFactory)
	for _, message := range messages {
		cached := loaded[string(KeyForRequest(message.RequestId))]
		request, ok := cached.(*RequestRecord)
		if !ok {
			continue
		}
		additional[string(KeyForCredit(request.SettlementDomainId, request.Requester))] = func() proto.Message { return new(CreditAccount) }
		for _, assignment := range request.Assignments {
			key := string(KeyForExecution(assignment.ExecutionId))
			if _, exists := loaded[key]; !exists {
				additional[key] = func() proto.Message { return new(ExecutionRecord) }
			}
		}
	}
	more, err := c.prefetchStateRecords(additional)
	if err != nil {
		return nil, err
	}
	for key, value := range more {
		loaded[key] = value
	}
	return loaded, nil
}

func (c *Contract) stageFinalizeRequestCertified(height uint64, message *MessageFinalizeRequest, batchCertified bool, records, loaded map[string]proto.Message, deletes *[][]byte) *PluginDeliverResponse {
	request := new(RequestRecord)
	if found, err := c.readExecutionStaged(records, loaded, KeyForRequest(message.RequestId), request); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || request.Status != "authorized" && request.Status != "ready" {
		return &PluginDeliverResponse{Error: ErrConflict("request is not active for execution settlement")}
	}
	if !validArchiveID(request.RequestArchiveId) || request.RequestArchiveId != "sha256:"+hex.EncodeToString(request.InputHash) {
		return &PluginDeliverResponse{Error: ErrState("request input archive evidence is unavailable")}
	}
	reservation := new(ReservationRecord)
	if !bytes.Equal(request.SettlementDomainId, message.SettlementDomainId) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("settlement domain does not match the authorized request")}
	}
	if found, err := c.readExecutionStaged(records, loaded, KeyForReservation(request.SettlementDomainId, message.RequestId), reservation); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || (reservation.Status != "reserved" && reservation.Status != "released") || reservation.Budget != message.ReservedBudget ||
		!bytes.Equal(reservation.Requester, request.Requester) {
		return &PluginDeliverResponse{Error: ErrState("request reservation is unavailable or inconsistent")}
	}
	reorgRepair := reservation.Status == "released"
	if len(message.ExecutionIds) == 0 {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("execution settlement evidence is incomplete")}
	}
	settling := make(map[string]*ExecutionRecord, len(message.ExecutionIds))
	for _, executionID := range message.ExecutionIds {
		if executionID == "" || settling[executionID] != nil {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("execution settlement identifiers must be unique")}
		}
		execution := new(ExecutionRecord)
		if found, err := c.readExecutionStaged(records, loaded, KeyForExecution(executionID), execution); err != nil {
			return &PluginDeliverResponse{Error: err}
		} else if !found || execution.RequestId != message.RequestId || execution.Settled {
			return &PluginDeliverResponse{Error: ErrConflict("execution is absent or already settled")}
		}
		settling[executionID] = execution
	}
	if message.FinalizesRequest {
		if message.RequestSpent != reservation.Spent {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("final settlement spend does not match Canopy accounting")}
		}
		if !allAssignmentsResolved(request) {
			return &PluginDeliverResponse{Error: ErrConflict("request still has unresolved execution assignments")}
		}
		for _, assignment := range request.Assignments {
			execution := settling[assignment.ExecutionId]
			if execution != nil {
				continue
			}
			execution = new(ExecutionRecord)
			if found, err := c.readExecutionStaged(records, loaded, KeyForExecution(assignment.ExecutionId), execution); err != nil {
				return &PluginDeliverResponse{Error: err}
			} else if !found || !execution.Settled {
				return &PluginDeliverResponse{Error: ErrConflict("request has an unsettled execution outside the final settlement transaction")}
			}
		}
	}
	subject := settlementSubject(message)
	claim := hashFields([]byte("settlement"), []byte(message.RequestId), stringListBytes(message.ExecutionIds), boolBytes(message.FinalizesRequest))
	reached := false
	if batchCertified {
		reached = true
	} else if message.ValidatorSetId != 0 || len(message.SignerBitmap) != 0 || len(message.AggregateSignature) != 0 {
		if certErr := c.verifyValidatorCertificate(subject, message.ValidatorSetId, message.SignerBitmap, message.AggregateSignature); certErr != nil {
			return &PluginDeliverResponse{Error: certErr}
		}
		reached = true
	} else {
		observation, observed, observeErr := c.observe(observationSettlement, subject, claim, message.ObserverAddress, height)
		if observeErr != nil {
			return &PluginDeliverResponse{Error: observeErr}
		}
		reached = observed
		for key, record := range observationRecords(observationSettlement, subject, claim, message.ObserverAddress, observation) {
			records[key] = record
		}
	}
	if !reached {
		// A minority observation is durable evidence, not a terminal settlement
		// transition. Keep discovery live until quorum or a certificate succeeds.
		return &PluginDeliverResponse{}
	}
	if reached {
		for executionID, execution := range settling {
			execution.Settled = true
			execution.SettlementTxHash = append([]byte(nil), message.SettlementTxHash...)
			records[string(KeyForExecution(executionID))] = execution
		}
		if !message.FinalizesRequest {
			if request.Status == "ready" && len(request.SettlementTxHash) != 0 {
				allSettled := true
				for _, assignment := range request.Assignments {
					if settling[assignment.ExecutionId] != nil {
						continue
					}
					execution := new(ExecutionRecord)
					if found, err := c.readExecutionStaged(records, loaded, KeyForExecution(assignment.ExecutionId), execution); err != nil {
						return &PluginDeliverResponse{Error: err}
					} else if !found || !execution.Settled {
						allSettled = false
						break
					}
				}
				if allSettled {
					request.Status = "settled"
					if reservation.Spent == 0 {
						request.Status = "failed"
					}
					records[string(KeyForRequest(request.RequestId))] = request
				}
			}
			if request.Status == "settled" || request.Status == "failed" {
				*deletes = append(*deletes, KeyForSettlementIndex(request.RequestId))
			}
			return &PluginDeliverResponse{}
		}
		if reorgRepair {
			request.Status = "settled"
			if reservation.Spent == 0 {
				request.Status = "failed"
			}
			request.SettlementTxHash = append([]byte(nil), message.SettlementTxHash...)
			records[string(KeyForRequest(message.RequestId))] = request
			*deletes = append(*deletes, KeyForSettlementIndex(request.RequestId))
			return &PluginDeliverResponse{}
		}
		if reservation.Spent > reservation.Budget {
			return &PluginDeliverResponse{Error: ErrState("request settlement does not match its reservation")}
		}
		credit := new(CreditAccount)
		if found, readErr := c.readExecutionStaged(records, loaded, KeyForCredit(request.SettlementDomainId, request.Requester), credit); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || credit.Reserved < reservation.Budget || !bytes.Equal(credit.Requester, request.Requester) ||
			^uint64(0)-credit.Settled < reservation.Spent || ^uint64(0)-credit.Released < reservation.Budget-reservation.Spent {
			return &PluginDeliverResponse{Error: ErrState("requester credit account cannot release the reservation")}
		}
		credit.Reserved -= reservation.Budget
		if credit.ProvisionalReserved < reservation.ProvisionalBudget {
			return &PluginDeliverResponse{Error: ErrState("requester provisional reservation is inconsistent")}
		}
		credit.ProvisionalReserved -= reservation.ProvisionalBudget
		credit.Settled += reservation.Spent
		credit.Released += reservation.Budget - reservation.Spent
		if _, valid := availableCredit(credit); !valid {
			return &PluginDeliverResponse{Error: ErrState("requester credit account invariant failed after settlement")}
		}
		reservation.Released = reservation.Budget - reservation.Spent
		reservation.Status = "released"
		reservation.ReleasedHeight = height
		request.Status = "settled"
		if reservation.Spent == 0 {
			request.Status = "failed"
		}
		request.SettlementTxHash = append([]byte(nil), message.SettlementTxHash...)
		records[string(KeyForRequest(message.RequestId))] = request
		records[string(KeyForReservation(request.SettlementDomainId, message.RequestId))] = reservation
		records[string(KeyForCredit(request.SettlementDomainId, request.Requester))] = credit
	}
	*deletes = append(*deletes, KeyForSettlementIndex(request.RequestId))
	return &PluginDeliverResponse{}
}

func (c *Contract) eligibleServicers(model string) ([]*Servicer, *PluginError) {
	entries, err := c.rangeRead(ActiveServicerPrefix())
	if err != nil {
		return nil, err
	}
	servicers := make([]*Servicer, 0, len(entries))
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return nil, paramsErr
	}
	for _, entry := range entries {
		marker := new(ReplayMarker)
		if err = Unmarshal(entry.Value, marker); err != nil {
			return nil, err
		}
		if !validAddress(marker.Id) {
			return nil, ErrState("active servicer index is invalid")
		}
		servicer := new(Servicer)
		if found, readErr := c.read(KeyForServicer(marker.Id), servicer); readErr != nil {
			return nil, readErr
		} else if !found || !servicer.Active || !bytes.Equal(servicer.OwnerAddress, marker.Id) {
			return nil, ErrState("active servicer index references invalid state")
		}
		if servicer.Bond < params.MinimumServicerBond || !containsString(servicer.Models, model) {
			continue
		}
		enclave := new(EnclaveKey)
		if found, readErr := c.read(KeyForEnclave(servicer.TeeKeyId), enclave); readErr != nil {
			return nil, readErr
		} else if !found || !enclave.Active || !bytes.Equal(enclave.OwnerAddress, servicer.OwnerAddress) {
			continue
		}
		servicers = append(servicers, servicer)
	}
	sort.Slice(servicers, func(i, j int) bool { return bytes.Compare(servicers[i].OwnerAddress, servicers[j].OwnerAddress) < 0 })
	return servicers, nil
}

func selectServicer(inputHash, previousBlockHash []byte, model string, attempt uint32, servicers []*Servicer) *Servicer {
	digest := hashFields([]byte("takusen:assignment"), inputHash, previousBlockHash, []byte(model), uint32Bytes(attempt))
	total := new(big.Int)
	for _, servicer := range servicers {
		total.Add(total, new(big.Int).SetUint64(servicer.Bond))
	}
	if total.Sign() == 0 {
		return servicers[new(big.Int).Mod(new(big.Int).SetBytes(digest), big.NewInt(int64(len(servicers)))).Int64()]
	}
	ticket := new(big.Int).Mod(new(big.Int).SetBytes(digest), total)
	cumulative := new(big.Int)
	for _, servicer := range servicers {
		cumulative.Add(cumulative, new(big.Int).SetUint64(servicer.Bond))
		if ticket.Cmp(cumulative) < 0 {
			return servicer
		}
	}
	return servicers[len(servicers)-1]
}

func findAssignment(request *RequestRecord, model string) *Assignment {
	for _, assignment := range request.Assignments {
		if assignment.Model == model {
			return assignment
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
