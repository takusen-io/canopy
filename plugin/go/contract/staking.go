package contract

import (
	"bytes"
	"math"
	"math/bits"

	"google.golang.org/protobuf/proto"
)

func accountSpendableAtHeight(account *Account, height uint64) uint64 {
	if account == nil {
		return 0
	}
	var locked uint64
	if account.VestingAmount != 0 {
		vestingLocked := account.VestingAmount
		if height >= account.VestingStartHeight && height >= account.VestingCliffHeight && account.VestingEndHeight > account.VestingStartHeight {
			if height >= account.VestingEndHeight {
				vestingLocked = 0
			} else {
				high, low := bits.Mul64(account.VestingAmount, height-account.VestingStartHeight)
				vested, _ := bits.Div64(high, low, account.VestingEndHeight-account.VestingStartHeight)
				vestingLocked -= min(vested, vestingLocked)
			}
		}
		locked = vestingLocked
	}
	if account.UnbondingAmount != 0 && height < account.UnbondingReleaseHeight {
		if locked > math.MaxUint64-account.UnbondingAmount {
			return 0
		}
		locked += account.UnbondingAmount
	}
	if locked >= account.Amount {
		return 0
	}
	return account.Amount - locked
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

func (c *Contract) slashableServicerBond(height uint64, owner []byte, servicer *Servicer, staged map[string]proto.Message) (uint64, *PluginError) {
	total := servicer.Bond
	account := new(Account)
	found, err := c.readStaged(staged, KeyForAccount(owner), account)
	if err != nil {
		return 0, err
	}
	if found && account.UnbondingAmount != 0 && height < account.UnbondingReleaseHeight {
		if ^uint64(0)-total < account.UnbondingAmount {
			return 0, ErrState("slashable servicer collateral overflows")
		}
		total += account.UnbondingAmount
	}
	return total, nil
}

func (c *Contract) applyServicerSlash(
	height uint64,
	evidenceID, owner []byte,
	reason string,
	params *ProtocolParams,
	records map[string]proto.Message,
	deletes *[][]byte,
) *PluginError {
	if found, err := c.readStaged(records, KeyForSlashEvidence(evidenceID), new(SlashEvidence)); err != nil {
		return err
	} else if found {
		return ErrConflict("slash evidence is already committed")
	}
	servicer := new(Servicer)
	if found, err := c.readStaged(records, KeyForServicer(owner), servicer); err != nil {
		return err
	} else if !found {
		return ErrNotFound("bonded slash target not found")
	}
	slashable, err := c.slashableServicerBond(height, owner, servicer, records)
	if err != nil {
		return err
	}
	if slashable == 0 {
		return ErrNotFound("bonded slash target not found")
	}
	penalty, valid := mulDiv64(slashable, uint64(params.InvalidReceiptSlashBps), 10_000)
	if !valid {
		return ErrState("servicer slash calculation overflow")
	}
	if params.InvalidReceiptSlashBps != 0 && penalty == 0 {
		penalty = 1
	}
	remaining := penalty
	activePenalty := min(remaining, servicer.Bond)
	servicer.Bond -= activePenalty
	remaining -= activePenalty
	if remaining != 0 {
		account := new(Account)
		found, readErr := c.readStaged(records, KeyForAccount(owner), account)
		if readErr != nil {
			return readErr
		}
		if !found || height >= account.UnbondingReleaseHeight || account.UnbondingAmount < remaining || account.Amount < remaining {
			return ErrState("servicer slash exceeds its unbonding collateral")
		}
		account.UnbondingAmount -= remaining
		account.Amount -= remaining
		if account.UnbondingAmount == 0 {
			account.UnbondingReleaseHeight = 0
		}
		remaining = 0
		records[string(KeyForAccount(owner))] = account
	}
	applied := penalty - remaining
	if ^uint64(0)-servicer.TotalSlashed < applied {
		return ErrState("servicer slash accounting overflow")
	}
	servicer.TotalSlashed += applied
	if servicer.Bond < params.MinimumServicerBond {
		servicer.Active = false
		*deletes = append(*deletes, KeyForActiveServicer(owner))
	}
	records[string(KeyForServicer(owner))] = servicer
	records[string(KeyForSlashEvidence(evidenceID))] = &SlashEvidence{
		EvidenceId: append([]byte(nil), evidenceID...), TargetAddress: append([]byte(nil), owner...),
		Reason: reason, Penalty: applied, ObservedHeight: height,
	}
	return nil
}
