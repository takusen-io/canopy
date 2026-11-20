package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"

	"google.golang.org/protobuf/proto"
)

func (c *Contract) deliverForceRevokeEnclave(height uint64, message *MessageForceRevokeEnclave) *PluginDeliverResponse {
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || enclave.Lifecycle == EnclaveLifecycle_ENCLAVE_LIFECYCLE_REVOKED {
		return &PluginDeliverResponse{Error: ErrNotFound("revocable enclave key not found")}
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
		enclave.Lifecycle = EnclaveLifecycle_ENCLAVE_LIFECYCLE_REVOKED
		records[string(KeyForEnclave(message.TeeKeyId))] = enclave
		servicer := new(Servicer)
		if found, readErr := c.read(KeyForServicer(enclave.OwnerAddress), servicer); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found && servicer.TeeKeyId == message.TeeKeyId {
			servicer.OwnerEnabled = false
			servicer.LifecycleNonce++
			records[string(KeyForServicer(enclave.OwnerAddress))] = servicer
			deletes = append(deletes, modelIndexKeys(servicer.Models, servicer.OwnerAddress)...)
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
		len(message.ProofSignature) != 0 || len(message.AttestationDocument) != 0 ||
		len(message.NativeRosterHash) != 0 || message.NativeValidatorSetId != 0
}

func modelIndexKeys(models []string, owner []byte) [][]byte {
	result := make([][]byte, 0, len(models))
	for _, model := range models {
		result = append(result, KeyForModelServicer(model, owner))
	}
	return result
}

func removedModelIndexKeys(oldModels, newModels []string, owner []byte, enabled bool) [][]byte {
	retained := make(map[string]struct{}, len(newModels))
	if enabled {
		for _, model := range newModels {
			retained[model] = struct{}{}
		}
	}
	result := make([][]byte, 0, len(oldModels))
	for _, model := range oldModels {
		if _, keep := retained[model]; !keep {
			result = append(result, KeyForModelServicer(model, owner))
		}
	}
	return result
}

func (c *Contract) ensureModelRosterCapacity(params *ProtocolParams, oldModels, newModels []string, enabled bool) *PluginError {
	if !enabled {
		return nil
	}
	old := make(map[string]struct{}, len(oldModels))
	for _, model := range oldModels {
		old[model] = struct{}{}
	}
	for _, model := range newModels {
		if _, retained := old[model]; retained {
			continue
		}
		entries, err := c.rangeRead(ModelServicerPrefix(model))
		if err != nil {
			return err
		}
		if uint32(len(entries)) >= params.MaxServicersPerModel {
			return ErrState("governed servicer roster is full for model " + model)
		}
	}
	return nil
}

func (c *Contract) currentNativeRoster() (uint64, []byte, *PluginError) {
	clock, err := c.currentEpochClockFromState()
	if err != nil {
		return 0, nil, err
	}
	hash, hashErr := c.epochValidatorRosterHash(clock.CurrentEpoch)
	if hashErr != nil {
		return 0, nil, hashErr
	}
	return clock.ValidatorSetId, hash, nil
}

// deliverManageServicer is the owner-authorized, block-effective lifecycle
// transition. Optimistic nonce/bond/debit guards make its broad atomic update
// safe against stale retries after a slash or another operator action.
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
		if message.LifecycleNonce != 0 || message.ExpectedBond != 0 || !message.OwnerEnabled ||
			message.Bond < params.MinimumServicerBond || message.TeeKeyId == "" || !attestationProvided(message) {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("new servicer registration requires nonce zero, an attested enclave, owner enablement, and the minimum bond")}
		}
		servicer.OwnerAddress = append([]byte(nil), message.OwnerAddress...)
		servicer.RegisteredHeight = height
	} else if message.LifecycleNonce != servicer.LifecycleNonce || message.ExpectedBond != servicer.Bond {
		return &PluginDeliverResponse{Error: ErrConflict("servicer lifecycle nonce or expected bond is stale")}
	}
	oldModels := append([]string(nil), servicer.Models...)
	oldEnabled := servicer.OwnerEnabled
	oldKeyID := servicer.TeeKeyId
	indexedOldModels := []string(nil)
	if oldEnabled {
		indexedOldModels = oldModels
	}
	if rosterErr := c.ensureModelRosterCapacity(params, indexedOldModels, message.Models, message.OwnerEnabled); rosterErr != nil {
		return &PluginDeliverResponse{Error: rosterErr}
	}
	records := map[string]proto.Message{}
	deletes := removedModelIndexKeys(oldModels, message.Models, message.OwnerAddress, message.OwnerEnabled)

	if message.Bond > servicer.Bond {
		increase := message.Bond - servicer.Bond
		if increase > message.MaxDebit {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("servicer bond debit exceeds the signed maximum")}
		}
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
			} else if found && bytes.Equal(oldKey.OwnerAddress, message.OwnerAddress) && oldKey.Lifecycle == EnclaveLifecycle_ENCLAVE_LIFECYCLE_ACTIVE {
				oldKey.Lifecycle = EnclaveLifecycle_ENCLAVE_LIFECYCLE_DRAINING
				records[string(KeyForEnclave(oldKeyID))] = oldKey
			}
		}
		servicer.TeeKeyId = ""
		servicer.LeaseExpiryHeight, servicer.LeaseCapacity, servicer.LeaseNonce = 0, 0, 0
		servicer.CapacityReservations = nil
	} else if !foundServicer || message.TeeKeyId != oldKeyID {
		if !attestationProvided(message) {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("enclave replacement requires fresh attestation")}
		}
		document, verifyErr := verifyNitroRegistration(message, params.NitroTrustRoot, timeMicros)
		if verifyErr != nil {
			return &PluginDeliverResponse{Error: verifyErr}
		}
		policy := pcrPolicyForMeasurements(params, document.PCRs[0], document.PCRs[1], document.PCRs[2])
		if policy == nil || policy.Lifecycle != PCRPolicyLifecycle_PCR_POLICY_LIFECYCLE_ADMITTING {
			return &PluginDeliverResponse{Error: ErrUnauthorized("enclave PCR policy is not admitting at this height")}
		}
		if found, readErr := c.read(KeyForEnclave(message.TeeKeyId), new(EnclaveKey)); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if found {
			return &PluginDeliverResponse{Error: ErrConflict("enclave key identifiers are terminal and cannot be reused")}
		}
		validatorSetID, rosterHash, rosterErr := c.currentNativeRoster()
		if rosterErr != nil {
			return &PluginDeliverResponse{Error: rosterErr}
		}
		if validatorSetID != message.NativeValidatorSetId || !bytes.Equal(rosterHash, message.NativeRosterHash) {
			return &PluginDeliverResponse{Error: ErrConflict("attested Native validator roster is stale")}
		}
		attestationHash := sha256.Sum256(message.AttestationDocument)
		records[string(KeyForEnclave(message.TeeKeyId))] = &EnclaveKey{
			OwnerAddress: append([]byte(nil), message.OwnerAddress...), TeeKeyId: message.TeeKeyId,
			PublicKey: append([]byte(nil), message.PublicKey...), AttestationHash: attestationHash[:],
			Pcr0: append([]byte(nil), document.PCRs[0]...), Pcr1: append([]byte(nil), document.PCRs[1]...),
			Pcr2: append([]byte(nil), document.PCRs[2]...), RegisteredHeight: height,
			Lifecycle: EnclaveLifecycle_ENCLAVE_LIFECYCLE_ACTIVE, PolicyId: policy.PolicyId,
			NativeRosterHash: append([]byte(nil), rosterHash...), NativeValidatorSetId: validatorSetID,
		}
		if oldKeyID != "" {
			oldKey := new(EnclaveKey)
			if found, readErr := c.read(KeyForEnclave(oldKeyID), oldKey); readErr != nil {
				return &PluginDeliverResponse{Error: readErr}
			} else if found && bytes.Equal(oldKey.OwnerAddress, message.OwnerAddress) && oldKey.Lifecycle == EnclaveLifecycle_ENCLAVE_LIFECYCLE_ACTIVE {
				oldKey.Lifecycle = EnclaveLifecycle_ENCLAVE_LIFECYCLE_DRAINING
				records[string(KeyForEnclave(oldKeyID))] = oldKey
			}
		}
		servicer.TeeKeyId = message.TeeKeyId
		servicer.LeaseExpiryHeight, servicer.LeaseCapacity, servicer.LeaseNonce = 0, 0, 0
		servicer.CapacityReservations = nil
	} else if attestationProvided(message) {
		return &PluginDeliverResponse{Error: ErrConflict("registered enclave key identifiers cannot be re-attested")}
	}

	servicer.Bond = message.Bond
	servicer.EvmPayoutAddress = append([]byte(nil), message.EvmPayoutAddress...)
	servicer.Models = append([]string(nil), message.Models...)
	servicer.OwnerEnabled = message.OwnerEnabled
	servicer.LifecycleNonce++
	// Every owner lifecycle transition invalidates the prior key-signed lease.
	// Preserve live reservations on same-key edits so a fresh lease cannot
	// overbook assignments that were already snapshotted.
	servicer.LeaseExpiryHeight, servicer.LeaseCapacity = 0, 0
	if servicer.OwnerEnabled && servicer.TeeKeyId == "" {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("owner-enabled servicer requires an enclave key")}
	}
	if servicer.OwnerEnabled {
		currentKey := new(EnclaveKey)
		if found, readErr := c.readStaged(records, KeyForEnclave(servicer.TeeKeyId), currentKey); readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		} else if !found || currentKey.Lifecycle != EnclaveLifecycle_ENCLAVE_LIFECYCLE_ACTIVE {
			return &PluginDeliverResponse{Error: ErrUnauthorized("owner-enabled servicer requires a non-retired active enclave key")}
		}
		policy := pcrPolicyByID(params, currentKey.PolicyId)
		if policy == nil || policy.Lifecycle != PCRPolicyLifecycle_PCR_POLICY_LIFECYCLE_ADMITTING {
			return &PluginDeliverResponse{Error: ErrUnauthorized("owner-enabled servicer requires an admitting enclave policy")}
		}
	}
	records[string(KeyForServicer(message.OwnerAddress))] = servicer
	if servicer.OwnerEnabled {
		for _, model := range servicer.Models {
			records[string(KeyForModelServicer(model, message.OwnerAddress))] = &ReplayMarker{Id: append([]byte(nil), message.OwnerAddress...)}
		}
	}
	return &PluginDeliverResponse{Error: c.writeChanges(records, deletes)}
}

func availabilityLeaseMessage(chainID uint64, message *MessageRenewServicerLease) []byte {
	var number [8]byte
	hash := sha256.New()
	write := func(value []byte) {
		binary.BigEndian.PutUint64(number[:], uint64(len(value)))
		_, _ = hash.Write(number[:])
		_, _ = hash.Write(value)
	}
	write([]byte("takusen:availability-lease:v1"))
	binary.BigEndian.PutUint64(number[:], chainID)
	write(number[:])
	write(message.OwnerAddress)
	write([]byte(message.TeeKeyId))
	binary.BigEndian.PutUint64(number[:], message.ExpiryHeight)
	write(number[:])
	binary.BigEndian.PutUint32(number[4:], message.Capacity)
	write(number[4:])
	binary.BigEndian.PutUint64(number[:], message.LifecycleNonce)
	write(number[:])
	binary.BigEndian.PutUint64(number[:], message.LeaseNonce)
	write(number[:])
	return hash.Sum(nil)
}

func (c *Contract) deliverRenewServicerLease(height uint64, message *MessageRenewServicerLease) *PluginDeliverResponse {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	if message.ExpiryHeight <= height || message.ExpiryHeight-height > params.MaxServicerLeaseBlocks ||
		message.Capacity == 0 || message.Capacity > params.MaxServicerCapacity {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("availability lease height or capacity is outside governed bounds")}
	}
	servicer := new(Servicer)
	if found, err := c.read(KeyForServicer(message.OwnerAddress), servicer); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || servicer.TeeKeyId != message.TeeKeyId || servicer.LifecycleNonce != message.LifecycleNonce ||
		message.LeaseNonce != servicer.LeaseNonce+1 {
		return &PluginDeliverResponse{Error: ErrConflict("availability lease targets stale servicer state")}
	}
	enclave := new(EnclaveKey)
	if found, err := c.read(KeyForEnclave(message.TeeKeyId), enclave); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || enclave.Lifecycle != EnclaveLifecycle_ENCLAVE_LIFECYCLE_ACTIVE ||
		!bytes.Equal(enclave.OwnerAddress, message.OwnerAddress) {
		return &PluginDeliverResponse{Error: ErrUnauthorized("availability lease requires the current active enclave")}
	}
	policy := pcrPolicyByID(params, enclave.PolicyId)
	if policy == nil || policy.Lifecycle != PCRPolicyLifecycle_PCR_POLICY_LIFECYCLE_ADMITTING {
		return &PluginDeliverResponse{Error: ErrUnauthorized("availability lease requires an admitting PCR policy")}
	}
	if !ed25519.Verify(enclave.PublicKey, availabilityLeaseMessage(c.Config.ChainId, message), message.EnclaveSignature) {
		return &PluginDeliverResponse{Error: ErrCrypto("invalid enclave availability signature")}
	}
	servicer.LeaseExpiryHeight = message.ExpiryHeight
	servicer.LeaseCapacity = message.Capacity
	servicer.LeaseNonce = message.LeaseNonce
	reservations := servicer.CapacityReservations[:0]
	for _, reservation := range servicer.CapacityReservations {
		if reservation != nil && reservation.DeadlineHeight > height {
			reservations = append(reservations, reservation)
		}
	}
	servicer.CapacityReservations = reservations
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{string(KeyForServicer(message.OwnerAddress)): servicer})}
}
