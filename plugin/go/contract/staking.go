package contract

import (
	"bytes"

	"google.golang.org/protobuf/proto"
)

func (c *Contract) deliverQueueServicerStake(height uint64, message *MessageQueueServicerStake) *PluginDeliverResponse {
	// Native rewards are minted exclusively on Base. Crediting them directly to
	// a Canopy bond would create stake without a corresponding Base mint and
	// bridge lock, so auto-compounding remains disabled until that cross-chain
	// flow exists.
	if message.AutoCompound {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("servicer auto-compound requires a Base mint and bridge flow")}
	}
	servicer := new(Servicer)
	if found, err := c.read(KeyForServicer(message.OwnerAddress), servicer); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found {
		return &PluginDeliverResponse{Error: ErrNotFound("servicer is not registered")}
	}
	if found, err := c.read(KeyForStakeChange(message.OwnerAddress), new(StakeChange)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("servicer already has a queued stake change")}
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if message.Active && message.TargetBond < params.MinimumServicerBond {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("active target bond is below the governed minimum")}
	}
	records := map[string]proto.Message{}
	var locked uint64
	if message.TargetBond > servicer.Bond {
		locked = message.TargetBond - servicer.Bond
		account := new(Account)
		if found, readErr := c.read(KeyForAccount(message.OwnerAddress), account); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || account.Amount < locked {
			return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
		}
		account.Amount -= locked
		records[string(KeyForAccount(message.OwnerAddress))] = account
	}
	clock, clockErr := c.currentEpochClock(params)
	if clockErr != nil {
		return &PluginDeliverResponse{Error: clockErr}
	}
	epoch := clock.CurrentEpoch
	records[string(KeyForStakeChange(message.OwnerAddress))] = &StakeChange{
		OwnerAddress: append([]byte(nil), message.OwnerAddress...), TargetBond: message.TargetBond,
		Active: message.Active, AutoCompound: false, EffectiveEpoch: epoch, LockedIncrease: locked,
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) deliverWithdrawUnbonded(height uint64, message *MessageWithdrawUnbonded) *PluginDeliverResponse {
	record := new(UnbondingRecord)
	if found, err := c.read(KeyForUnbonding(message.OwnerAddress, message.Sequence), record); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || record.Withdrawn {
		return &PluginDeliverResponse{Error: ErrNotFound("withdrawable unbonding record not found")}
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	clock, clockErr := c.currentEpochClock(params)
	if clockErr != nil {
		return &PluginDeliverResponse{Error: clockErr}
	}
	completedEpoch := clock.CurrentEpoch - 1
	if completedEpoch < record.ReleaseEpoch {
		return &PluginDeliverResponse{Error: ErrConflict("unbonding period has not elapsed")}
	}
	account := new(Account)
	found, readErr := c.read(KeyForAccount(message.OwnerAddress), account)
	if readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	}
	if !found {
		account.Address = append([]byte(nil), message.OwnerAddress...)
	}
	if ^uint64(0)-account.Amount < record.Amount {
		return &PluginDeliverResponse{Error: ErrState("unbonding withdrawal overflows account")}
	}
	account.Amount += record.Amount
	record.Withdrawn = true
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{
		string(KeyForAccount(message.OwnerAddress)):                     account,
		string(KeyForUnbonding(message.OwnerAddress, message.Sequence)): record,
	})}
}

func (c *Contract) deliverSetProducerPayout(message *MessageSetProducerPayout) *PluginDeliverResponse {
	eligible, err := c.producerPayoutEligible(message.OwnerAddress)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if !eligible {
		return &PluginDeliverResponse{Error: ErrUnauthorized("producer payout owner is not a current, prepared, or proven producer")}
	}
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{
		string(KeyForProducerPayout(message.OwnerAddress)): &ProducerPayout{
			OwnerAddress: append([]byte(nil), message.OwnerAddress...), CanonicalChainAddress: append([]byte(nil), message.CanonicalChainAddress...),
		},
	})}
}

func (c *Contract) producerPayoutEligible(owner []byte) (bool, *PluginError) {
	produced := new(ProducerIdentity)
	if found, err := c.read(KeyForProducerIdentity(owner), produced); err != nil {
		return false, err
	} else if found {
		return bytes.Equal(produced.OwnerAddress, owner), nil
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return false, err
	}
	clock, err := c.currentEpochClock(params)
	if err != nil {
		return false, err
	}
	for _, epoch := range []uint64{clock.CurrentEpoch, clock.CurrentEpoch + 1} {
		if epoch == 0 {
			continue
		}
		validator := new(Validator)
		if found, readErr := c.read(KeyForEpochValidator(epoch, owner), validator); readErr != nil {
			return false, readErr
		} else if found && bytes.Equal(validator.Address, owner) && !validator.Delegate &&
			validator.StakedAmount >= params.MinimumValidatorBond && containsCommittee(validator.Committees, c.Config.ChainId) {
			return true, nil
		}
	}
	return false, nil
}

func (c *Contract) deliverObserveSlashEvidence(height uint64, message *MessageObserveSlashEvidence) *PluginDeliverResponse {
	if found, err := c.read(KeyForSlashEvidence(message.EvidenceId), new(SlashEvidence)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("slash evidence is already committed")}
	}
	servicer := new(Servicer)
	if found, err := c.read(KeyForServicer(message.TargetAddress), servicer); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || servicer.Bond == 0 {
		return &PluginDeliverResponse{Error: ErrNotFound("bonded slash target not found")}
	}
	subject := hashFields([]byte("takusen:slash-evidence"), message.EvidenceId, message.TargetAddress, []byte(message.Reason))
	claim := hashFields([]byte("slash-evidence"), message.EvidenceId)
	observation, reached, err := c.observe(observationSlashEvidence, subject, claim, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := observationRecords(observationSlashEvidence, subject, claim, message.ObserverAddress, observation)
	if reached {
		params, paramsErr := c.currentProtocolParams()
		if paramsErr != nil {
			return &PluginDeliverResponse{Error: paramsErr}
		}
		clock, clockErr := c.currentEpochClock(params)
		if clockErr != nil {
			return &PluginDeliverResponse{Error: clockErr}
		}
		bps := params.TimeoutSlashBps
		if message.Reason == "invalid_receipt" {
			bps = params.InvalidReceiptSlashBps
		}
		penalty, validPenalty := mulDiv64(servicer.Bond, uint64(bps), 10_000)
		if !validPenalty {
			return &PluginDeliverResponse{Error: ErrState("servicer slash calculation overflow")}
		}
		if bps != 0 && penalty == 0 {
			penalty = 1
		}
		records[string(KeyForSlashEvidence(message.EvidenceId))] = &SlashEvidence{
			EvidenceId: append([]byte(nil), message.EvidenceId...), TargetAddress: append([]byte(nil), message.TargetAddress...),
			Reason: message.Reason, Penalty: penalty, ObservedHeight: height,
			EffectiveEpoch: clock.CurrentEpoch, Status: "queued",
		}
		records[string(KeyForPendingSlash(clock.CurrentEpoch, message.EvidenceId))] = &ReplayMarker{Id: append([]byte(nil), message.EvidenceId...)}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) applyEpochStakeChanges(epoch uint64, params *ProtocolParams, records map[string]proto.Message) ([][]byte, *PluginError) {
	entries, err := c.rangeRead(StakeChangePrefix())
	if err != nil {
		return nil, err
	}
	deletes := make([][]byte, 0)
	for _, entry := range entries {
		change := new(StakeChange)
		if decodeErr := Unmarshal(entry.Value, change); decodeErr != nil {
			return nil, decodeErr
		}
		if change.EffectiveEpoch > epoch {
			continue
		}
		servicer := new(Servicer)
		if found, readErr := c.read(KeyForServicer(change.OwnerAddress), servicer); readErr != nil {
			return nil, readErr
		} else if !found {
			return nil, ErrState("queued stake change references missing servicer")
		}
		if change.TargetBond > servicer.Bond && change.TargetBond-servicer.Bond != change.LockedIncrease {
			return nil, ErrState("queued stake increase is not fully locked")
		}
		if change.TargetBond < servicer.Bond {
			amount := servicer.Bond - change.TargetBond
			key := KeyForUnbonding(change.OwnerAddress, epoch)
			if found, readErr := c.read(key, new(UnbondingRecord)); readErr != nil {
				return nil, readErr
			} else if found {
				return nil, ErrState("duplicate unbonding sequence")
			}
			records[string(key)] = &UnbondingRecord{
				OwnerAddress: append([]byte(nil), change.OwnerAddress...), Sequence: epoch,
				Amount: amount, ReleaseEpoch: epoch + params.UnbondingEpochs,
			}
		}
		wasActive := servicer.Active
		servicer.Bond = change.TargetBond
		servicer.Active = change.Active && change.TargetBond >= params.MinimumServicerBond
		servicer.AutoCompound = false
		records[string(KeyForServicer(change.OwnerAddress))] = servicer
		if servicer.Active {
			records[string(KeyForActiveServicer(change.OwnerAddress))] = &ReplayMarker{Id: append([]byte(nil), change.OwnerAddress...)}
		} else if wasActive {
			deletes = append(deletes, KeyForActiveServicer(change.OwnerAddress))
		}
		deletes = append(deletes, append([]byte(nil), entry.Key...))
	}
	return deletes, nil
}

func (c *Contract) applyEpochSlashes(epoch uint64, params *ProtocolParams, records map[string]proto.Message, limit uint64) ([][]byte, bool, *PluginError) {
	entries, err := c.rangeReadPage(PendingSlashPrefix(), nil, limit+1)
	if err != nil {
		return nil, false, err
	}
	deletes := make([][]byte, 0, min(len(entries), int(limit)))
	for index, entry := range entries {
		if uint64(index) == limit {
			marker := new(ReplayMarker)
			if decodeErr := Unmarshal(entry.Value, marker); decodeErr != nil {
				return nil, false, decodeErr
			}
			next := new(SlashEvidence)
			if found, readErr := c.read(KeyForSlashEvidence(marker.Id), next); readErr != nil {
				return nil, false, readErr
			} else if !found {
				return nil, false, ErrState("pending slash index references missing evidence")
			}
			return deletes, next.EffectiveEpoch > epoch, nil
		}
		marker := new(ReplayMarker)
		if decodeErr := Unmarshal(entry.Value, marker); decodeErr != nil {
			return nil, false, decodeErr
		}
		evidence := new(SlashEvidence)
		if found, readErr := c.read(KeyForSlashEvidence(marker.Id), evidence); readErr != nil {
			return nil, false, readErr
		} else if !found {
			return nil, false, ErrState("pending slash index references missing evidence")
		}
		if evidence.EffectiveEpoch > epoch {
			return deletes, true, nil
		}
		if evidence.Status != "queued" {
			return nil, false, ErrState("pending slash index references non-queued evidence")
		}
		servicer := new(Servicer)
		if found, readErr := c.readStaged(records, KeyForServicer(evidence.TargetAddress), servicer); readErr != nil {
			return nil, false, readErr
		} else if !found {
			return nil, false, ErrState("slash evidence references missing servicer")
		}
		penalty := evidence.Penalty
		if penalty > servicer.Bond {
			penalty = servicer.Bond
		}
		servicer.Bond -= penalty
		if ^uint64(0)-servicer.TotalSlashed < penalty {
			return nil, false, ErrState("servicer slash accounting overflow")
		}
		servicer.TotalSlashed += penalty
		if servicer.Bond < params.MinimumServicerBond {
			servicer.Active = false
			deletes = append(deletes, KeyForActiveServicer(evidence.TargetAddress))
		}
		evidence.Penalty, evidence.Status = penalty, "applied"
		records[string(KeyForServicer(evidence.TargetAddress))] = servicer
		records[string(KeyForSlashEvidence(evidence.EvidenceId))] = evidence
		deletes = append(deletes, append([]byte(nil), entry.Key...))
	}
	return deletes, true, nil
}
