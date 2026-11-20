package contract

import (
	"bytes"
	"crypto/sha256"

	"google.golang.org/protobuf/proto"
)

func (c *Contract) deliverForceRevokeEnclave(height uint64, message *MessageForceRevokeEnclave) *PluginDeliverResponse {
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || !enclave.Active {
		return &PluginDeliverResponse{Error: ErrNotFound("active enclave key not found")}
	}
	subject := revocationSubject(message)
	claim := hashFields([]byte("revocation"), []byte(message.TeeKeyId))
	observation, reached, err := c.observe(observationRevocation, subject, claim, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := observationRecords(observationRevocation, subject, claim, message.ObserverAddress, observation)
	var deletes [][]byte
	if reached {
		enclave.Active = false
		records[string(KeyForEnclave(message.TeeKeyId))] = enclave
		entries, readErr := c.rangeRead(ServicerPrefix())
		if readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		}
		for _, entry := range entries {
			servicer := new(Servicer)
			if decodeErr := Unmarshal(entry.Value, servicer); decodeErr != nil {
				return &PluginDeliverResponse{Error: ErrState("invalid servicer record")}
			}
			if servicer.TeeKeyId != message.TeeKeyId {
				continue
			}
			servicer.Active = false
			records[string(entry.Key)] = servicer
			deletes = append(deletes, KeyForActiveServicer(servicer.OwnerAddress))
		}
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
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

func attestationProvided(message *MessageManageServicer) bool {
	return len(message.PublicKey) != 0 || len(message.Nonce) != 0 || len(message.UserData) != 0 ||
		len(message.ProofSignature) != 0 || len(message.AttestationDocument) != 0
}

// deliverManageServicer is the owner-authorized, block-effective lifecycle
// transition. It atomically manages registration, configuration, target bond,
// activation, and enclave rotation or removal.
func (c *Contract) deliverManageServicer(height, timeMicros uint64, message *MessageManageServicer) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if modelErr := validateServicerModels(params, message.Models); modelErr != nil {
		return &PluginDeliverResponse{Error: modelErr}
	}

	servicer := new(Servicer)
	foundServicer, err := c.read(KeyForServicer(message.OwnerAddress), servicer)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if !foundServicer {
		if !message.Active || message.Bond < params.MinimumServicerBond || message.TeeKeyId == "" || !attestationProvided(message) {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("new servicer registration requires an active attested enclave and the minimum bond")}
		}
		servicer.OwnerAddress = append([]byte(nil), message.OwnerAddress...)
		servicer.RegisteredHeight = height
	}
	wasActive := servicer.Active
	oldKeyID := servicer.TeeKeyId
	records := map[string]proto.Message{}
	var deletes [][]byte

	if message.Bond > servicer.Bond {
		increase := message.Bond - servicer.Bond
		account := new(Account)
		if found, readErr := c.read(KeyForAccount(message.OwnerAddress), account); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || accountSpendableAtHeight(account, height) < increase {
			return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
		}
		account.Amount -= increase
		records[string(KeyForAccount(message.OwnerAddress))] = account
	} else if message.Bond < servicer.Bond {
		decrease := servicer.Bond - message.Bond
		account := new(Account)
		if found, readErr := c.read(KeyForAccount(message.OwnerAddress), account); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found {
			account.Address = append([]byte(nil), message.OwnerAddress...)
		}
		if ^uint64(0)-account.Amount < decrease || ^uint64(0)-height < params.ServicerUnbondingBlocks {
			return &PluginDeliverResponse{Error: ErrState("servicer bond reduction overflows its unbonding balance")}
		}
		account.Amount += decrease
		releaseHeight := height + params.ServicerUnbondingBlocks
		if account.UnbondingAmount == 0 || height >= account.UnbondingReleaseHeight {
			account.UnbondingAmount = decrease
			account.UnbondingReleaseHeight = releaseHeight
		} else {
			if ^uint64(0)-account.UnbondingAmount < decrease {
				return &PluginDeliverResponse{Error: ErrState("servicer unbonding balance overflow")}
			}
			account.UnbondingAmount += decrease
			if releaseHeight > account.UnbondingReleaseHeight {
				account.UnbondingReleaseHeight = releaseHeight
			}
		}
		records[string(KeyForAccount(message.OwnerAddress))] = account
	}

	if message.TeeKeyId == "" {
		if oldKeyID != "" {
			oldKey := new(EnclaveKey)
			if found, readErr := c.read(KeyForEnclave(oldKeyID), oldKey); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if found && bytes.Equal(oldKey.OwnerAddress, message.OwnerAddress) {
				oldKey.Active = false
				records[string(KeyForEnclave(oldKeyID))] = oldKey
			}
		}
		servicer.TeeKeyId = ""
	} else if !foundServicer || message.TeeKeyId != oldKeyID || attestationProvided(message) {
		if !attestationProvided(message) {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("enclave replacement requires fresh attestation")}
		}
		document, verifyErr := verifyNitroRegistration(message, params.NitroTrustRoot, timeMicros)
		if verifyErr != nil {
			return &PluginDeliverResponse{Error: verifyErr}
		}
		if !pcrApproved(params, document.PCRs[0], document.PCRs[1], document.PCRs[2]) {
			return &PluginDeliverResponse{Error: ErrUnauthorized("enclave PCR measurements are not governed at this height")}
		}
		existing := new(EnclaveKey)
		if found, readErr := c.read(KeyForEnclave(message.TeeKeyId), existing); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found && !bytes.Equal(existing.OwnerAddress, message.OwnerAddress) {
			return &PluginDeliverResponse{Error: ErrConflict("replacement enclave key is registered to another owner")}
		}
		attestationHash := sha256.Sum256(message.AttestationDocument)
		records[string(KeyForEnclave(message.TeeKeyId))] = &EnclaveKey{
			OwnerAddress: append([]byte(nil), message.OwnerAddress...), TeeKeyId: message.TeeKeyId,
			PublicKey: append([]byte(nil), message.PublicKey...), AttestationHash: attestationHash[:],
			Pcr0: append([]byte(nil), document.PCRs[0]...), Pcr1: append([]byte(nil), document.PCRs[1]...),
			Pcr2: append([]byte(nil), document.PCRs[2]...), RegisteredHeight: height, Active: true,
		}
		if oldKeyID != "" && oldKeyID != message.TeeKeyId {
			oldKey := new(EnclaveKey)
			if found, readErr := c.read(KeyForEnclave(oldKeyID), oldKey); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if found && bytes.Equal(oldKey.OwnerAddress, message.OwnerAddress) {
				oldKey.Active = false
				records[string(KeyForEnclave(oldKeyID))] = oldKey
			}
		}
		servicer.TeeKeyId = message.TeeKeyId
	}

	servicer.Bond = message.Bond
	servicer.EvmPayoutAddress = append([]byte(nil), message.EvmPayoutAddress...)
	servicer.Models = append([]string(nil), message.Models...)
	servicer.Active = message.Active
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
		if !enclave.Active || !bytes.Equal(enclave.OwnerAddress, message.OwnerAddress) {
			return &PluginDeliverResponse{Error: ErrUnauthorized("active servicer requires an active owned enclave key")}
		}
	}
	records[string(KeyForServicer(message.OwnerAddress))] = servicer
	if servicer.Active {
		records[string(KeyForActiveServicer(message.OwnerAddress))] = &ReplayMarker{Id: append([]byte(nil), message.OwnerAddress...)}
	} else if wasActive {
		deletes = append(deletes, KeyForActiveServicer(message.OwnerAddress))
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}
