package contract

import (
	"bytes"
	"crypto/sha256"

	"google.golang.org/protobuf/proto"
)

func (c *Contract) applyEnclaveRevocation(message *EnclaveRevocation, records map[string]proto.Message, deletes *[][]byte) bool {
	if checkEnclaveRevocation(message) != nil {
		return false
	}
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return false
	} else if !found || enclave.Status == "revoked" {
		return false
	}
	enclave.Status = "revoked"
	records[string(KeyForEnclave(message.TeeKeyId))] = enclave
	servicer := new(Servicer)
	if found, readErr := c.read(KeyForServicer(enclave.OwnerAddress), servicer); readErr != nil {
		return false
	} else if found && servicer.TeeKeyId == message.TeeKeyId && servicer.Active {
		servicer.Active = false
		if servicer.Revision == ^uint64(0) {
			return false
		}
		servicer.Revision++
		records[string(KeyForServicer(enclave.OwnerAddress))] = servicer
		*deletes = append(*deletes, KeyForActiveServicer(enclave.OwnerAddress))
	}
	return true
}

func validateServicerModels(params *ProtocolParams, models []string) *PluginError {
	if len(params.Models) == 0 {
		return nil
	}
	for _, model := range models {
		if modelPolicy(params, model) == nil {
			return ErrUnauthorized("servicer model is not governed")
		}
	}
	return nil
}

// deliverRegisterServicer atomically registers the first enclave, locks the
// initial bond, and creates the active servicer record.
func (c *Contract) deliverRegisterServicer(height, timeMicros uint64, message *MessageRegisterServicer) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if message.Bond < params.MinimumServicerBond {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("servicer bond is below the governed minimum")}
	}
	if modelErr := validateServicerModels(params, message.Models); modelErr != nil {
		return &PluginDeliverResponse{Error: modelErr}
	}
	if found, err := c.read(KeyForServicer(message.OwnerAddress), new(Servicer)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("servicer is already registered")}
	}
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), new(EnclaveKey)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("enclave key is already registered")}
	}
	document, verifyErr := verifyNitroRegistration(message, params.NitroTrustRoot, timeMicros)
	if verifyErr != nil {
		return &PluginDeliverResponse{Error: verifyErr}
	}
	if !pcrApproved(params, document.PCRs[0], document.PCRs[1], document.PCRs[2]) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("enclave PCR measurements are not governed at this height")}
	}
	account := new(Account)
	if found, err := c.read(KeyForAccount(message.OwnerAddress), account); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || accountSpendableAtHeight(account, height) < message.Bond {
		return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
	}
	account.Amount -= message.Bond
	attestationHash := sha256.Sum256(message.AttestationDocument)
	servicer := &Servicer{
		OwnerAddress: append([]byte(nil), message.OwnerAddress...), EvmPayoutAddress: append([]byte(nil), message.EvmPayoutAddress...),
		TeeKeyId: message.TeeKeyId, Models: append([]string(nil), message.Models...), Bond: message.Bond,
		Active: true, RegisteredHeight: height, Revision: 1,
	}
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{
		string(KeyForAccount(message.OwnerAddress)): account,
		string(KeyForEnclave(message.TeeKeyId)): &EnclaveKey{
			OwnerAddress: append([]byte(nil), message.OwnerAddress...), TeeKeyId: message.TeeKeyId,
			PublicKey: append([]byte(nil), message.PublicKey...), AttestationHash: attestationHash[:],
			Pcr0: append([]byte(nil), document.PCRs[0]...), Pcr1: append([]byte(nil), document.PCRs[1]...),
			Pcr2: append([]byte(nil), document.PCRs[2]...), RegisteredHeight: height, Status: "active",
		},
		string(KeyForServicer(message.OwnerAddress)):       servicer,
		string(KeyForActiveServicer(message.OwnerAddress)): &ReplayMarker{Id: append([]byte(nil), message.OwnerAddress...)},
	})}
}

// deliverManageServicer applies only the explicitly supplied components while
// preserving one atomic owner transition. The revision rejects stale targets
// without forcing unchanged configuration into every transaction.
func (c *Contract) deliverManageServicer(height, timeMicros uint64, message *MessageManageServicer) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}

	servicer := new(Servicer)
	if found, err := c.read(KeyForServicer(message.OwnerAddress), servicer); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found {
		return &PluginDeliverResponse{Error: ErrNotFound("servicer is not registered")}
	}
	if servicer.Revision != message.ExpectedRevision {
		return &PluginDeliverResponse{Error: ErrConflict("servicer revision changed")}
	}
	wasActive := servicer.Active
	oldKeyID := servicer.TeeKeyId
	records := map[string]proto.Message{}
	var deletes [][]byte
	changed := false

	if update := message.Bond; update != nil && update.TargetBond > servicer.Bond {
		increase := update.TargetBond - servicer.Bond
		if increase > update.MaxDebit {
			return &PluginDeliverResponse{Error: ErrConflict("servicer bond increase exceeds its debit bound")}
		}
		account := new(Account)
		if found, readErr := c.read(KeyForAccount(message.OwnerAddress), account); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || accountSpendableAtHeight(account, height) < increase {
			return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
		}
		account.Amount -= increase
		records[string(KeyForAccount(message.OwnerAddress))] = account
		servicer.Bond = update.TargetBond
		changed = true
	} else if update := message.Bond; update != nil && update.TargetBond < servicer.Bond {
		decrease := servicer.Bond - update.TargetBond
		account := new(Account)
		if found, readErr := c.read(KeyForAccount(message.OwnerAddress), account); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found {
			account.Address = append([]byte(nil), message.OwnerAddress...)
		}
		if ^uint64(0)-account.Amount < decrease || ^uint64(0)-height < params.ServicerUnbondingBlocks {
			return &PluginDeliverResponse{Error: ErrState("servicer bond reduction overflows its locked balance")}
		}
		account.Amount += decrease
		releaseHeight := height + params.ServicerUnbondingBlocks
		if account.UnbondingAmount == 0 || height >= account.UnbondingReleaseHeight {
			account.UnbondingAmount = decrease
			account.UnbondingReleaseHeight = releaseHeight
		} else {
			if ^uint64(0)-account.UnbondingAmount < decrease {
				return &PluginDeliverResponse{Error: ErrState("servicer locked balance overflow")}
			}
			account.UnbondingAmount += decrease
			if releaseHeight > account.UnbondingReleaseHeight {
				account.UnbondingReleaseHeight = releaseHeight
			}
		}
		records[string(KeyForAccount(message.OwnerAddress))] = account
		servicer.Bond = update.TargetBond
		changed = true
	} else if message.Bond != nil {
		return &PluginDeliverResponse{Error: ErrConflict("servicer bond target is unchanged")}
	}

	if rotation := message.Rotation; rotation != nil {
		if rotation.TeeKeyId == oldKeyID {
			return &PluginDeliverResponse{Error: ErrConflict("replacement enclave key must differ from the current key")}
		}
		document, verifyErr := verifyNitroRegistration(rotation, params.NitroTrustRoot, timeMicros)
		if verifyErr != nil {
			return &PluginDeliverResponse{Error: verifyErr}
		}
		if !pcrApproved(params, document.PCRs[0], document.PCRs[1], document.PCRs[2]) {
			return &PluginDeliverResponse{Error: ErrUnauthorized("enclave PCR measurements are not governed at this height")}
		}
		existing := new(EnclaveKey)
		if found, readErr := c.read(KeyForEnclave(rotation.TeeKeyId), existing); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found {
			return &PluginDeliverResponse{Error: ErrConflict("replacement enclave key is already registered")}
		}
		attestationHash := sha256.Sum256(rotation.AttestationDocument)
		records[string(KeyForEnclave(rotation.TeeKeyId))] = &EnclaveKey{
			OwnerAddress: append([]byte(nil), message.OwnerAddress...), TeeKeyId: rotation.TeeKeyId,
			PublicKey: append([]byte(nil), rotation.PublicKey...), AttestationHash: attestationHash[:],
			Pcr0: append([]byte(nil), document.PCRs[0]...), Pcr1: append([]byte(nil), document.PCRs[1]...),
			Pcr2: append([]byte(nil), document.PCRs[2]...), RegisteredHeight: height, Status: "active",
		}
		oldKey := new(EnclaveKey)
		if oldKeyID == "" {
			return &PluginDeliverResponse{Error: ErrState("registered servicer has no enclave key to rotate")}
		}
		if found, readErr := c.read(KeyForEnclave(oldKeyID), oldKey); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || !bytes.Equal(oldKey.OwnerAddress, message.OwnerAddress) {
			return &PluginDeliverResponse{Error: ErrState("current servicer enclave key is unavailable or has the wrong owner")}
		}
		oldKey.Status = "draining"
		records[string(KeyForEnclave(oldKeyID))] = oldKey
		servicer.TeeKeyId = rotation.TeeKeyId
		changed = true
	}

	if update := message.Configuration; update != nil {
		if modelErr := validateServicerModels(params, update.Models); modelErr != nil {
			return &PluginDeliverResponse{Error: modelErr}
		}
		configurationChanged := !bytes.Equal(servicer.EvmPayoutAddress, update.EvmPayoutAddress) ||
			!equalStrings(servicer.Models, update.Models) || servicer.Active != update.Active
		if !configurationChanged {
			return &PluginDeliverResponse{Error: ErrConflict("servicer configuration is unchanged")}
		}
		servicer.EvmPayoutAddress = append([]byte(nil), update.EvmPayoutAddress...)
		servicer.Models = append([]string(nil), update.Models...)
		servicer.Active = update.Active
		changed = true
	}
	if !changed {
		return &PluginDeliverResponse{Error: ErrConflict("servicer management has no effect")}
	}
	if servicer.Active {
		if servicer.Bond < params.MinimumServicerBond {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("active servicer bond is below the governed minimum")}
		}
		enclave := new(EnclaveKey)
		if staged, ok := records[string(KeyForEnclave(servicer.TeeKeyId))]; ok {
			enclave = proto.Clone(staged).(*EnclaveKey)
		} else if found, readErr := c.read(KeyForEnclave(servicer.TeeKeyId), enclave); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found {
			return &PluginDeliverResponse{Error: ErrUnauthorized("active servicer requires an active owned enclave key")}
		}
		if enclave.Status != "active" || !bytes.Equal(enclave.OwnerAddress, message.OwnerAddress) {
			return &PluginDeliverResponse{Error: ErrUnauthorized("active servicer requires an active owned enclave key")}
		}
	}
	if servicer.Revision == ^uint64(0) {
		return &PluginDeliverResponse{Error: ErrState("servicer revision overflow")}
	}
	servicer.Revision++
	records[string(KeyForServicer(message.OwnerAddress))] = servicer
	if servicer.Active {
		records[string(KeyForActiveServicer(message.OwnerAddress))] = &ReplayMarker{Id: append([]byte(nil), message.OwnerAddress...)}
	} else if wasActive {
		deletes = append(deletes, KeyForActiveServicer(message.OwnerAddress))
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
