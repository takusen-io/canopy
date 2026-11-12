package contract

import (
	"bytes"
	"encoding/hex"
	"math/big"

	"google.golang.org/protobuf/proto"
)

const (
	observationEnclave           byte = 1
	observationAuthorization     byte = 2
	observationSettlement        byte = 3
	observationReassignment      byte = 4
	observationRevocation        byte = 5
	observationDeposit           byte = 6
	observationValidatorRotation byte = 7
	observationBridgeLock        byte = 8
	observationSlashEvidence     byte = 9
	observationBridgeRelease     byte = 10
	observationDepositResolve    byte = 11
	observationSettlementReorg   byte = 12
	observationEpochMint         byte = 13
)

func enclaveSubject(message *MessageObserveEnclave) []byte {
	return hashFields(
		[]byte("takusen:enclave-registration"), message.OwnerAddress, []byte(message.TeeKeyId),
		message.PublicKey, message.AttestationHash, message.Pcr0, message.Pcr1, message.Pcr2,
		message.Nonce, message.UserData, message.ProofSignature, message.AttestationDocument,
	)
}

func revocationSubject(message *MessageRevokeEnclave) []byte {
	return hashFields([]byte("takusen:enclave-revocation"), []byte(message.TeeKeyId))
}

func depositSubject(message *MessageObserveDeposit) []byte {
	return hashFields(
		[]byte("takusen:settlement-deposit"), message.SettlementDomainId, message.ChainTxHash, message.Requester,
		uint64Bytes(message.AmountMicros), message.TokenAmount, []byte{boolByte(message.Provisional)},
	)
}

func depositResolutionSubject(message *MessageResolveDeposit) []byte {
	return hashFields([]byte("takusen:settlement-deposit-resolution"), message.SettlementDomainId, message.ChainTxHash, []byte(message.Resolution))
}

func settlementReorgSubject(message *MessageResolveSettlement) []byte {
	return hashFields(
		[]byte("takusen:settlement-reorg"), message.SettlementDomainId, []byte(message.RequestId),
		message.SettlementTxHash, stringListBytes(message.ExecutionIds), boolBytes(message.FinalizesRequest),
	)
}

func boolByte(value bool) byte {
	if value {
		return 1
	}
	return 0
}

func authorizationSubject(message *MessageObserveAuthorization) []byte {
	return hashFields(
		[]byte("takusen:signed-authorization"), []byte(message.RequestId), message.InputHash,
		message.SettlementDomainId,
		message.Requester, uint64Bytes(message.ReservedBudget), []byte(message.OutputType),
		stringListBytes(message.Models), uint32Bytes(message.ExecutionQuorum),
		uint64Bytes(uint64(message.OutputMinimum)), uint64Bytes(uint64(message.OutputMaximum)),
		stringListBytes(message.OutputChoices), message.SchemaHash,
		uint64Bytes(message.DeadlineHeight), message.AuthorizationSignature, uint64Bytes(message.AuthorizationDeadline),
		[]byte(message.RequestArchiveId), uint64Bytes(message.AuthorizationChainBlockNumber), message.AuthorizationChainBlockHash,
	)
}

func settlementSubject(message *MessageFinalizeRequest) []byte {
	// This historical domain label is consensus data; keep it even though the
	// subject now binds one atomic settlement transaction.
	return hashFields(
		[]byte("takusen:settlement-finalization"), message.SettlementDomainId, []byte(message.RequestId),
		message.SettlementTxHash, uint64Bytes(message.ReservedBudget), uint64Bytes(message.RequestSpent), stringListBytes(message.ExecutionIds), boolBytes(message.FinalizesRequest),
	)
}

func settlementBatchSubject(messages []*MessageFinalizeRequest) []byte {
	fields := make([][]byte, 1, len(messages)+1)
	fields[0] = []byte("takusen:settlement-finalization-batch")
	for _, message := range messages {
		fields = append(fields, settlementSubject(message))
	}
	return hashFields(fields...)
}

func boolBytes(value bool) []byte {
	if value {
		return []byte{1}
	}
	return []byte{0}
}

func reassignmentSubject(message *MessageReassignRequest, attempt uint32) []byte {
	return hashFields(
		[]byte("takusen:reassignment"), []byte(message.RequestId), []byte(message.Model),
		uint32Bytes(attempt), uint64Bytes(message.NewDeadlineHeight),
	)
}

func (c *Contract) observe(kind byte, subject, claim, observer []byte, height uint64) (*Observation, bool, *PluginError) {
	snapshot, err := c.activeValidatorSnapshot()
	if err != nil {
		return nil, false, err
	}
	observerValidator, exists := snapshot.validators[hex.EncodeToString(observer)]
	if !exists {
		return nil, false, ErrUnauthorized("observer is not an active validator in this committee")
	}
	prior := new(Observation)
	claimKey := KeyForObservationClaim(kind, snapshot.validatorSetID, snapshot.epoch, claim, observer)
	if found, readErr := c.read(claimKey, prior); readErr != nil {
		return nil, false, readErr
	} else if found {
		if bytes.Equal(prior.SubjectHash, subject) {
			return nil, false, ErrConflict("validator already submitted this observation")
		}
		return nil, false, ErrConflict("validator submitted conflicting content for this claim")
	}
	entries, err := c.rangeRead(ObservationSubjectPrefix(kind, snapshot.validatorSetID, snapshot.epoch, subject))
	if err != nil {
		return nil, false, err
	}
	observedStake := new(big.Int).SetUint64(observerValidator.StakedAmount)
	for _, entry := range entries {
		observation := new(Observation)
		if err = Unmarshal(entry.Value, observation); err != nil {
			return nil, false, err
		}
		if bytes.Equal(observation.ObserverAddress, observer) {
			return nil, false, ErrConflict("validator already submitted this observation")
		}
		validator, found := snapshot.validators[hex.EncodeToString(observation.ObserverAddress)]
		if !found || !bytes.Equal(observation.ClaimHash, claim) ||
			observation.ValidatorSetId != snapshot.validatorSetID || observation.ValidatorEpoch != snapshot.epoch ||
			observation.TotalWeight != snapshot.totalStake || observation.ObserverWeight != validator.StakedAmount {
			return nil, false, ErrState("stored observation does not match its immutable validator snapshot")
		}
		observedStake.Add(observedStake, new(big.Int).SetUint64(observation.ObserverWeight))
	}
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return nil, false, paramsErr
	}
	left := new(big.Int).Mul(observedStake, new(big.Int).SetUint64(uint64(params.QuorumDenominator)))
	right := new(big.Int).Mul(new(big.Int).SetUint64(snapshot.totalStake), new(big.Int).SetUint64(uint64(params.QuorumNumerator)))
	return &Observation{
		SubjectHash: subject, ObserverAddress: observer, ObservedHeight: height, ClaimHash: claim,
		ValidatorSetId: snapshot.validatorSetID, ObserverWeight: observerValidator.StakedAmount,
		TotalWeight: snapshot.totalStake, ValidatorEpoch: snapshot.epoch,
	}, left.Cmp(right) > 0, nil
}

func observationRecords(kind byte, subject, claim, observer []byte, observation *Observation) map[string]proto.Message {
	return map[string]proto.Message{
		string(KeyForObservation(kind, observation.ValidatorSetId, observation.ValidatorEpoch, subject, observer)):    observation,
		string(KeyForObservationClaim(kind, observation.ValidatorSetId, observation.ValidatorEpoch, claim, observer)): observation,
	}
}

type activeValidatorSnapshot struct {
	validators     map[string]*Validator
	totalStake     uint64
	epoch          uint64
	validatorSetID uint64
}

func (c *Contract) activeValidatorSnapshot() (*activeValidatorSnapshot, *PluginError) {
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return nil, paramsErr
	}
	clock, clockErr := c.currentEpochClock(params)
	if clockErr != nil {
		return nil, clockErr
	}
	entries, err := c.rangeRead(EpochValidatorPrefix(clock.CurrentEpoch))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrState("active validator snapshot is unavailable")
	}
	validators := make(map[string]*Validator)
	var total uint64
	for _, entry := range entries {
		validator := new(Validator)
		if err = Unmarshal(entry.Value, validator); err != nil {
			return nil, err
		}
		if !validAddress(validator.Address) || validator.StakedAmount == 0 {
			return nil, ErrState("active validator snapshot contains an invalid member")
		}
		if ^uint64(0)-total < validator.StakedAmount {
			return nil, ErrState("validator stake overflow")
		}
		total += validator.StakedAmount
		key := hex.EncodeToString(validator.Address)
		if _, duplicate := validators[key]; duplicate {
			return nil, ErrState("active validator snapshot contains a duplicate member")
		}
		validators[key] = validator
	}
	if total == 0 {
		return nil, ErrState("Takusen requires an active validator committee")
	}
	return &activeValidatorSnapshot{validators: validators, totalStake: total, epoch: clock.CurrentEpoch, validatorSetID: clock.ValidatorSetId}, nil
}

func (c *Contract) activeValidators() (map[string]*Validator, uint64, *PluginError) {
	snapshot, err := c.activeValidatorSnapshot()
	if err != nil {
		return nil, 0, err
	}
	return snapshot.validators, snapshot.totalStake, nil
}

func containsCommittee(committees []uint64, chainID uint64) bool {
	for _, committee := range committees {
		if committee == chainID {
			return true
		}
	}
	return false
}
