package contract

import "google.golang.org/protobuf/proto"

func (c *Contract) deliverObserveEnclave(height uint64, message *MessageObserveEnclave) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if !pcrApproved(params, message.Pcr0, message.Pcr1, message.Pcr2) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("enclave PCR measurements are not governed")}
	}
	if params.RequireNitroAttestation && len(message.AttestationDocument) == 0 {
		return &PluginDeliverResponse{Error: ErrUnauthorized("governance requires Nitro attestation evidence")}
	}
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), new(EnclaveKey)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("enclave key is already registered")}
	}
	subject := enclaveSubject(message)
	claim := hashFields([]byte("enclave"), []byte(message.TeeKeyId))
	observation, reached, err := c.observe(observationEnclave, subject, claim, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := observationRecords(observationEnclave, subject, claim, message.ObserverAddress, observation)
	if reached {
		records[string(KeyForEnclave(message.TeeKeyId))] = &EnclaveKey{
			OwnerAddress: message.OwnerAddress, TeeKeyId: message.TeeKeyId, PublicKey: message.PublicKey,
			AttestationHash: message.AttestationHash, Pcr0: message.Pcr0, Pcr1: message.Pcr1, Pcr2: message.Pcr2,
			RegisteredHeight: height, Active: true,
		}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

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

func (c *Contract) deliverRegisterServicer(height uint64, message *MessageRegisterServicer) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if message.Bond < params.MinimumServicerBond {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("servicer bond is below the governed minimum")}
	}
	if !payoutsCoverActiveDomains(params, message.Payouts) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("servicer payouts must cover every active settlement domain exactly once")}
	}
	if len(params.Models) != 0 {
		for _, model := range message.Models {
			if modelPolicy(params, model) == nil {
				return &PluginDeliverResponse{Error: ErrUnauthorized("servicer model is not governed")}
			}
		}
	}
	if found, err := c.read(KeyForServicer(message.OwnerAddress), new(Servicer)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("servicer is already registered")}
	}
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || !enclave.Active || string(enclave.OwnerAddress) != string(message.OwnerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("servicer does not own an active enclave key")}
	}
	account := new(Account)
	if found, err := c.read(KeyForAccount(message.OwnerAddress), account); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || account.Amount < message.Bond {
		return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
	}
	account.Amount -= message.Bond
	servicer := &Servicer{
		OwnerAddress: message.OwnerAddress, Payouts: clonePayouts(message.Payouts), TeeKeyId: message.TeeKeyId,
		Models: append([]string(nil), message.Models...), Bond: message.Bond, Active: true, RegisteredHeight: height,
	}
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{
		string(KeyForAccount(message.OwnerAddress)):        account,
		string(KeyForServicer(message.OwnerAddress)):       servicer,
		string(KeyForActiveServicer(message.OwnerAddress)): &ReplayMarker{Id: append([]byte(nil), message.OwnerAddress...)},
	})}
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
	if !payoutsCoverActiveDomains(params, message.Payouts) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("servicer payouts must cover every active settlement domain exactly once")}
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
	servicer.Payouts = clonePayouts(message.Payouts)
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

func payoutsCoverActiveDomains(params *ProtocolParams, payouts []*SettlementPayout) bool {
	wanted := make(map[string]struct{})
	for _, domain := range params.SettlementDomains {
		if domain != nil && domain.Active {
			wanted[string(domain.Id)] = struct{}{}
		}
	}
	if len(wanted) == 0 || len(wanted) != len(payouts) {
		return false
	}
	for _, payout := range payouts {
		if payout == nil {
			return false
		}
		if _, ok := wanted[string(payout.SettlementDomainId)]; !ok {
			return false
		}
	}
	return true
}

func clonePayouts(payouts []*SettlementPayout) []*SettlementPayout {
	result := make([]*SettlementPayout, len(payouts))
	for index, payout := range payouts {
		result[index] = &SettlementPayout{SettlementDomainId: append([]byte(nil), payout.SettlementDomainId...), Address: append([]byte(nil), payout.Address...)}
	}
	return result
}
