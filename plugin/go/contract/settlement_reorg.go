package contract

import (
	"bytes"
)

// deliverResolveSettlement reopens exactly the execution segment lost from
// Base. Requester accounting remains final: operators bear reorg timing risk,
// so a repair neither claws back released credit nor charges the requester a
// second time.
func (c *Contract) deliverResolveSettlement(height uint64, message *MessageResolveSettlement) *PluginDeliverResponse {
	request := new(RequestRecord)
	if found, err := c.read(KeyForRequest(message.RequestId), request); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found {
		return &PluginDeliverResponse{Error: ErrConflict("settlement is not an active reorg candidate")}
	}
	if !bytes.Equal(request.SettlementDomainId, message.SettlementDomainId) {
		return &PluginDeliverResponse{Error: ErrConflict("settlement domain does not match request")}
	}
	if message.FinalizesRequest && ((request.Status != "settled" && request.Status != "failed") ||
		!bytes.Equal(request.SettlementTxHash, message.SettlementTxHash)) {
		return &PluginDeliverResponse{Error: ErrConflict("settlement is not an active reorg candidate")}
	}
	executions := make(map[string]*ExecutionRecord, len(message.ExecutionIds))
	for _, executionID := range message.ExecutionIds {
		execution := new(ExecutionRecord)
		if found, err := c.read(KeyForExecution(executionID), execution); err != nil {
			return &PluginDeliverResponse{Error: err}
		} else if !found || execution.RequestId != message.RequestId || !bytes.Equal(execution.SettlementDomainId, message.SettlementDomainId) || !execution.Settled ||
			!bytes.Equal(execution.SettlementTxHash, message.SettlementTxHash) {
			return &PluginDeliverResponse{Error: ErrConflict("settlement execution is not an active reorg candidate")}
		}
		executions[executionID] = execution
	}
	subject := settlementReorgSubject(message)
	claim := hashFields([]byte("settlement-reorg"), []byte(message.RequestId), stringListBytes(message.ExecutionIds), boolBytes(message.FinalizesRequest))
	observation, reached, err := c.observe(observationSettlementReorg, subject, claim, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := observationRecords(observationSettlementReorg, subject, claim, message.ObserverAddress, observation)
	if !reached {
		return &PluginDeliverResponse{Error: c.write(records)}
	}
	for executionID, execution := range executions {
		execution.Settled = false
		execution.SettlementTxHash = nil
		records[string(KeyForExecution(executionID))] = execution
	}
	if !message.FinalizesRequest && (request.Status == "settled" || request.Status == "failed") {
		request.Status = "ready"
		records[string(KeyForRequest(request.RequestId))] = request
	}
	if message.FinalizesRequest {
		reservation := new(ReservationRecord)
		if found, readErr := c.read(KeyForReservation(message.SettlementDomainId, message.RequestId), reservation); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || reservation.Status != "released" {
			return &PluginDeliverResponse{Error: ErrState("reorganized settlement reservation is inconsistent")}
		}
		request.Status = "ready"
		request.SettlementTxHash = nil
		records[string(KeyForRequest(request.RequestId))] = request
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}
