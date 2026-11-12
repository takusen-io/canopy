package contract

import (
	"bytes"
	"math/big"
	"sort"

	"google.golang.org/protobuf/proto"
)

func (c *Contract) deliverObserveDeposit(height uint64, message *MessageObserveDeposit) *PluginDeliverResponse {
	return c.deliverObserveDepositCertified(height, message, false)
}

func (c *Contract) deliverObserveDepositCertified(height uint64, message *MessageObserveDeposit, certified bool) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	domain, domainErr := settlementDomain(params, message.SettlementDomainId, true)
	if domainErr != nil {
		return &PluginDeliverResponse{Error: domainErr}
	}
	if normalized, valid := normalizeTokenAmount(message.TokenAmount, domain.TokenDecimals); !valid || normalized != message.AmountMicros {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("deposit token amount does not exactly normalize to micro-units")}
	}
	if found, err := c.read(KeyForDeposit(message.SettlementDomainId, message.ChainTxHash), new(DepositRecord)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("deposit transaction is already witnessed")}
	}
	subject := depositSubject(message)
	claim := hashFields([]byte("deposit"), message.ChainTxHash)
	reached := certified
	records := make(map[string]proto.Message)
	if !certified {
		observation, observed, err := c.observe(observationDeposit, subject, claim, message.ObserverAddress, height)
		if err != nil {
			return &PluginDeliverResponse{Error: err}
		}
		reached = observed
		records = observationRecords(observationDeposit, subject, claim, message.ObserverAddress, observation)
	}
	if reached {
		account := new(CreditAccount)
		found, readErr := c.read(KeyForCredit(message.SettlementDomainId, message.Requester), account)
		if readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		}
		if !found {
			account.Requester = append([]byte(nil), message.Requester...)
			account.SettlementDomainId = append([]byte(nil), message.SettlementDomainId...)
		}
		if !bytes.Equal(account.Requester, message.Requester) || !bytes.Equal(account.SettlementDomainId, message.SettlementDomainId) || ^uint64(0)-account.Deposited < message.AmountMicros {
			return &PluginDeliverResponse{Error: ErrState("deposit credit account is invalid or overflowed")}
		}
		account.Deposited += message.AmountMicros
		if message.Provisional {
			if ^uint64(0)-account.Provisional < message.AmountMicros {
				return &PluginDeliverResponse{Error: ErrState("provisional deposit credit overflowed")}
			}
			account.Provisional += message.AmountMicros
		}
		records[string(KeyForCredit(message.SettlementDomainId, message.Requester))] = account
		status := "finalized"
		if message.Provisional {
			status = "provisional"
		}
		records[string(KeyForDeposit(message.SettlementDomainId, message.ChainTxHash))] = &DepositRecord{
			ChainTxHash: append([]byte(nil), message.ChainTxHash...), Requester: append([]byte(nil), message.Requester...),
			Amount: message.AmountMicros, ObservedHeight: height, Status: status,
			SettlementDomainId: append([]byte(nil), message.SettlementDomainId...), TokenAmount: append([]byte(nil), message.TokenAmount...),
		}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func availableCredit(account *CreditAccount) (uint64, bool) {
	if account.Provisional > account.Deposited || account.ProvisionalReserved > account.Reserved ||
		account.Settled > account.Deposited || account.Reserved > account.Deposited-account.Settled {
		return 0, false
	}
	return account.Deposited - account.Settled - account.Reserved, true
}

func safeAvailableCredit(account *CreditAccount) (uint64, bool) {
	if _, valid := availableCredit(account); !valid {
		return 0, false
	}
	finalDeposited := account.Deposited - account.Provisional
	finalReserved := account.Reserved - account.ProvisionalReserved
	if finalDeposited < account.Settled+finalReserved {
		return 0, false
	}
	return finalDeposited - account.Settled - finalReserved, true
}

func (c *Contract) deliverResolveDeposit(height uint64, message *MessageResolveDeposit) *PluginDeliverResponse {
	deposit := new(DepositRecord)
	if found, err := c.read(KeyForDeposit(message.SettlementDomainId, message.ChainTxHash), deposit); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found {
		return &PluginDeliverResponse{Error: ErrNotFound("provisional deposit not found")}
	} else if deposit.Status != "provisional" {
		return &PluginDeliverResponse{Error: ErrConflict("deposit is not provisional")}
	}
	subject := depositResolutionSubject(message)
	claim := hashFields([]byte("deposit-resolution"), message.ChainTxHash)
	observation, reached, err := c.observe(observationDepositResolve, subject, claim, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := observationRecords(observationDepositResolve, subject, claim, message.ObserverAddress, observation)
	if !reached {
		return &PluginDeliverResponse{Error: c.write(records)}
	}
	credit := new(CreditAccount)
	deletes := make([][]byte, 0)
	if found, readErr := c.read(KeyForCredit(message.SettlementDomainId, deposit.Requester), credit); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || !bytes.Equal(deposit.SettlementDomainId, message.SettlementDomainId) || !bytes.Equal(credit.SettlementDomainId, message.SettlementDomainId) || !bytes.Equal(credit.Requester, deposit.Requester) || credit.Provisional < deposit.Amount {
		return &PluginDeliverResponse{Error: ErrState("provisional deposit credit account is inconsistent")}
	}
	reservations, readErr := c.reservationsFor(message.SettlementDomainId, deposit.Requester)
	if readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	}
	credit.Provisional -= deposit.Amount
	switch message.Resolution {
	case "finalized":
		deposit.Status = "finalized"
		// Final backing promotes the oldest provisional reservations first. Any
		// remainder simply becomes finalized available credit.
		sort.Slice(reservations, func(i, j int) bool {
			if reservations[i].ReservedHeight == reservations[j].ReservedHeight {
				return reservations[i].RequestId < reservations[j].RequestId
			}
			return reservations[i].ReservedHeight < reservations[j].ReservedHeight
		})
		remaining := deposit.Amount
		for _, reservation := range reservations {
			if remaining == 0 || (reservation.Status != "reserved" && reservation.Status != "released") || reservation.ProvisionalBudget == 0 {
				continue
			}
			promoted := reservation.ProvisionalBudget
			if promoted > remaining {
				promoted = remaining
			}
			reservation.ProvisionalBudget -= promoted
			if reservation.ProvisionalBudget == 0 {
				deletes = append(deletes, KeyForProvisionalReservation(message.SettlementDomainId, reservation.Requester, reservation.RequestId))
			}
			if reservation.Status == "reserved" {
				if credit.ProvisionalReserved < promoted {
					return &PluginDeliverResponse{Error: ErrState("provisional reservation promotion underflow")}
				}
				credit.ProvisionalReserved -= promoted
			}
			remaining -= promoted
			records[string(KeyForReservation(message.SettlementDomainId, reservation.RequestId))] = reservation
		}
	case "reorged":
		if credit.Deposited < deposit.Amount {
			return &PluginDeliverResponse{Error: ErrState("reorged deposit exceeds credited deposits")}
		}
		credit.Deposited -= deposit.Amount
		if ^uint64(0)-credit.Reorged < deposit.Amount {
			return &PluginDeliverResponse{Error: ErrState("reorged deposit accounting overflowed")}
		}
		credit.Reorged += deposit.Amount
		deposit.Status = "reorged"
		// Newest provisional reservations are orphaned first. A whole request is
		// orphaned even if only part of its budget depended on the losing fork;
		// the requester is never charged again for already returned work.
		sort.Slice(reservations, func(i, j int) bool {
			if reservations[i].ReservedHeight == reservations[j].ReservedHeight {
				return reservations[i].RequestId > reservations[j].RequestId
			}
			return reservations[i].ReservedHeight > reservations[j].ReservedHeight
		})
		for _, reservation := range reservations {
			if credit.Settled <= credit.Deposited && credit.Reserved <= credit.Deposited-credit.Settled {
				break
			}
			if (reservation.Status != "reserved" && reservation.Status != "released") || reservation.ProvisionalBudget == 0 {
				continue
			}
			if reservation.Status == "reserved" {
				if credit.Reserved < reservation.Budget || credit.ProvisionalReserved < reservation.ProvisionalBudget {
					return &PluginDeliverResponse{Error: ErrState("provisional reservation accounting is inconsistent")}
				}
				credit.Reserved -= reservation.Budget
				credit.ProvisionalReserved -= reservation.ProvisionalBudget
			} else {
				if credit.Settled < reservation.Spent || credit.Released < reservation.Released {
					return &PluginDeliverResponse{Error: ErrState("provisional settlement accounting is inconsistent")}
				}
				credit.Settled -= reservation.Spent
				credit.Released -= reservation.Released
			}
			reservation.Status = "orphaned_reorg"
			reservation.ProvisionalBudget = 0
			deletes = append(deletes, KeyForProvisionalReservation(message.SettlementDomainId, reservation.Requester, reservation.RequestId))
			records[string(KeyForReservation(message.SettlementDomainId, reservation.RequestId))] = reservation
			request := new(RequestRecord)
			if found, requestErr := c.read(KeyForRequest(reservation.RequestId), request); requestErr != nil {
				return &PluginDeliverResponse{Error: requestErr}
			} else if !found {
				return &PluginDeliverResponse{Error: ErrState("orphaned request is missing")}
			}
			request.Status = "orphaned_reorg"
			records[string(KeyForRequest(request.RequestId))] = request
		}
	default:
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("unsupported deposit resolution")}
	}
	deposit.ResolvedHeight = height
	if _, valid := availableCredit(credit); !valid {
		return &PluginDeliverResponse{Error: ErrState("credit account cannot absorb the settlement-chain reorg")}
	}
	records[string(KeyForDeposit(message.SettlementDomainId, message.ChainTxHash))] = deposit
	records[string(KeyForCredit(message.SettlementDomainId, deposit.Requester))] = credit
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

func (c *Contract) reservationsFor(domainID, requester []byte) ([]*ReservationRecord, *PluginError) {
	entries, err := c.rangeRead(ProvisionalReservationPrefix(domainID, requester))
	if err != nil {
		return nil, err
	}
	result := make([]*ReservationRecord, 0)
	for _, entry := range entries {
		marker := new(ReplayMarker)
		if err = Unmarshal(entry.Value, marker); err != nil {
			return nil, err
		}
		if len(marker.Id) == 0 {
			return nil, ErrState("provisional reservation index is invalid")
		}
		record := new(ReservationRecord)
		if found, readErr := c.read(KeyForReservation(domainID, string(marker.Id)), record); readErr != nil {
			return nil, readErr
		} else if !found || !bytes.Equal(record.Requester, requester) || record.ProvisionalBudget == 0 {
			return nil, ErrState("provisional reservation index references invalid state")
		}
		result = append(result, proto.Clone(record).(*ReservationRecord))
	}
	return result, nil
}

func normalizeTokenAmount(encoded []byte, decimals uint32) (uint64, bool) {
	if len(encoded) == 0 || len(encoded) > 32 || decimals < 6 || decimals > 36 {
		return 0, false
	}
	value := new(big.Int).SetBytes(encoded)
	if value.Sign() <= 0 {
		return 0, false
	}
	if decimals > 6 {
		divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(decimals-6)), nil)
		quotient, remainder := new(big.Int), new(big.Int)
		quotient.QuoRem(value, divisor, remainder)
		if remainder.Sign() != 0 {
			return 0, false
		}
		value = quotient
	}
	return value.Uint64(), value.IsUint64() && value.Sign() > 0
}
