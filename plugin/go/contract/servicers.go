package contract

import (
	"crypto/sha256"

	"google.golang.org/protobuf/proto"
)

func (c *Contract) deliverRevokeEnclave(height uint64, message *MessageRevokeEnclave) *PluginDeliverResponse {
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
	deletes := make([][]byte, 0, 1)
	if reached {
		enclave.Active = false
		records[string(KeyForEnclave(message.TeeKeyId))] = enclave
		servicer := new(Servicer)
		if found, readErr := c.read(KeyForServicer(enclave.OwnerAddress), servicer); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found && servicer.TeeKeyId == message.TeeKeyId && servicer.Active {
			servicer.Active = false
			records[string(KeyForServicer(enclave.OwnerAddress))] = servicer
			deletes = append(deletes, KeyForActiveServicer(enclave.OwnerAddress))
		}
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

func (c *Contract) deliverRegisterServicer(height, timeMicros uint64, message *MessageRegisterServicer) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if message.Bond < params.MinimumServicerBond {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("servicer bond is below the governed minimum")}
	}
	if len(params.Models) != 0 {
		for _, model := range message.Models {
			if modelPolicy(params, model) == nil {
				return &PluginDeliverResponse{Error: ErrUnauthorized("servicer model is not governed")}
			}
		}
	}
	document, verifyErr := verifyNitroRegistration(message, params.NitroTrustRoot, timeMicros)
	if verifyErr != nil {
		return &PluginDeliverResponse{Error: verifyErr}
	}
	if !pcrApproved(params, document.PCRs[0], document.PCRs[1], document.PCRs[2]) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("enclave PCR measurements are not governed at this height")}
	}
	existingEnclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), existingEnclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found && string(existingEnclave.OwnerAddress) != string(message.OwnerAddress) {
		return &PluginDeliverResponse{Error: ErrConflict("enclave key is registered to another owner")}
	}
	servicer := new(Servicer)
	foundServicer, err := c.read(KeyForServicer(message.OwnerAddress), servicer)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	additionalBond := message.Bond
	if foundServicer {
		additionalBond = 0
		if servicer.Bond < message.Bond {
			additionalBond = message.Bond - servicer.Bond
		}
	} else {
		servicer.OwnerAddress = append([]byte(nil), message.OwnerAddress...)
		servicer.RegisteredHeight = height
	}
	records := map[string]proto.Message{}
	if additionalBond != 0 {
		account := new(Account)
		if found, readErr := c.read(KeyForAccount(message.OwnerAddress), account); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || account.Amount < additionalBond {
			return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
		}
		account.Amount -= additionalBond
		records[string(KeyForAccount(message.OwnerAddress))] = account
		servicer.Bond += additionalBond
	}
	servicer.EvmPayoutAddress = append([]byte(nil), message.EvmPayoutAddress...)
	servicer.TeeKeyId = message.TeeKeyId
	servicer.Models = append([]string(nil), message.Models...)
	servicer.Active = true
	attestationHash := sha256.Sum256(message.AttestationDocument)
	records[string(KeyForEnclave(message.TeeKeyId))] = &EnclaveKey{
		OwnerAddress: append([]byte(nil), message.OwnerAddress...), TeeKeyId: message.TeeKeyId,
		PublicKey: append([]byte(nil), message.PublicKey...), AttestationHash: attestationHash[:],
		Pcr0: append([]byte(nil), document.PCRs[0]...), Pcr1: append([]byte(nil), document.PCRs[1]...),
		Pcr2: append([]byte(nil), document.PCRs[2]...), RegisteredHeight: height, Active: true,
	}
	records[string(KeyForServicer(message.OwnerAddress))] = servicer
	records[string(KeyForActiveServicer(message.OwnerAddress))] = &ReplayMarker{Id: append([]byte(nil), message.OwnerAddress...)}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) deliverUpdateServicer(message *MessageUpdateServicer) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if len(params.Models) != 0 {
		for _, model := range message.Models {
			if modelPolicy(params, model) == nil {
				return &PluginDeliverResponse{Error: ErrUnauthorized("servicer model is not governed")}
			}
		}
	}
	servicer := new(Servicer)
	if found, err := c.read(KeyForServicer(message.OwnerAddress), servicer); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found {
		return &PluginDeliverResponse{Error: ErrNotFound("servicer is not registered")}
	}
	wasActive := servicer.Active
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || !enclave.Active || string(enclave.OwnerAddress) != string(message.OwnerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("servicer does not own an active enclave key")}
	}
	records := map[string]proto.Message{}
	if message.AdditionalBond != 0 {
		if ^uint64(0)-servicer.Bond < message.AdditionalBond {
			return &PluginDeliverResponse{Error: ErrState("servicer bond overflow")}
		}
		account := new(Account)
		if found, err := c.read(KeyForAccount(message.OwnerAddress), account); err != nil {
			return &PluginDeliverResponse{Error: err}
		} else if !found || account.Amount < message.AdditionalBond {
			return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
		}
		account.Amount -= message.AdditionalBond
		servicer.Bond += message.AdditionalBond
		records[string(KeyForAccount(message.OwnerAddress))] = account
	}
	servicer.EvmPayoutAddress = append([]byte(nil), message.EvmPayoutAddress...)
	servicer.TeeKeyId = message.TeeKeyId
	servicer.Models = append([]string(nil), message.Models...)
	servicer.Active = message.Active
	if servicer.Bond < params.MinimumServicerBond {
		servicer.Active = false
	}
	records[string(KeyForServicer(message.OwnerAddress))] = servicer
	deletes := make([][]byte, 0, 1)
	if servicer.Active {
		records[string(KeyForActiveServicer(message.OwnerAddress))] = &ReplayMarker{Id: append([]byte(nil), message.OwnerAddress...)}
	} else if wasActive {
		deletes = append(deletes, KeyForActiveServicer(message.OwnerAddress))
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}
