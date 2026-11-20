package contract

import (
	"bytes"
	"crypto/sha256"
	"math"
	"sort"

	"google.golang.org/protobuf/proto"
)

const epochRewardsType = "EpochRewards(uint256 chainId,address token,uint64 validatorSetId,uint64 epoch,bytes32 recipientsHash,bytes32 amountsHash)"
const validatorEpochOpenSeconds uint64 = 1_200
const validatorEpochDurationSeconds uint64 = 3_600
const validatorMinimumHandoffNoticeSeconds uint64 = 1_200

func (c *Contract) endBlock(request *PluginEndRequest) *PluginEndResponse {
	if request == nil || request.Height == 0 || !validAddress(request.ProposerAddress) {
		return &PluginEndResponse{Error: ErrInvalidTransaction("end block is missing a valid proposer")}
	}
	if request.TimeMicros == 0 {
		return &PluginEndResponse{Error: ErrInvalidTransaction("end block is missing its consensus timestamp")}
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginEndResponse{Error: err}
	}
	clock, err := c.currentEpochClock(params)
	if err != nil {
		return &PluginEndResponse{Error: err}
	}
	if request.Height < clock.StartHeight {
		return &PluginEndResponse{Error: ErrState("block height moved before the current epoch")}
	}
	clock.ConsensusTimeSeconds = request.TimeMicros / 1_000_000
	if clock.StartTimestamp == 0 {
		clock.StartTimestamp = clock.ConsensusTimeSeconds
		clock.FreezeTimestamp = clock.StartTimestamp + validatorEpochOpenSeconds
		clock.NominalEndTimestamp = clock.StartTimestamp + validatorEpochDurationSeconds
		clock.StartHeight = request.Height
	}
	freezeTimestamp, epochHandoffTimestamp, phaseErr := validatorEpochPhaseTimes(clock)
	if phaseErr != nil {
		return &PluginEndResponse{Error: phaseErr}
	}
	if clock.ConsensusTimeSeconds < clock.StartTimestamp {
		return &PluginEndResponse{Error: ErrState("epoch consensus time moved before its start")}
	}
	epoch := clock.CurrentEpoch
	producer := new(ProducerRecord)
	key := KeyForProducer(epoch, request.ProposerAddress)
	found, readErr := c.read(key, producer)
	if readErr != nil {
		return &PluginEndResponse{Error: readErr}
	}
	if !found {
		producer.Epoch = epoch
		producer.ProducerAddress = append([]byte(nil), request.ProposerAddress...)
	}
	if producer.Blocks == ^uint64(0) {
		return &PluginEndResponse{Error: ErrState("producer block counter overflow")}
	}
	producer.Blocks++
	records := map[string]proto.Message{
		string(key): producer, string(KeyForEpochClock()): clock,
		string(KeyForProducerIdentity(request.ProposerAddress)): &ProducerIdentity{OwnerAddress: append([]byte(nil), request.ProposerAddress...)},
	}
	var deletes [][]byte
	if !clock.ValidatorRosterFrozen && clock.ConsensusTimeSeconds < freezeTimestamp {
		accountingDeletes, accountingErr := c.processPendingEpochAccounting(records)
		if accountingErr != nil {
			return &PluginEndResponse{Error: accountingErr}
		}
		deletes = append(deletes, accountingDeletes...)
		return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.writeChanges(records, deletes)})
	}
	if !clock.ValidatorRosterFrozen {
		// The first block at or after S + 1,200 seconds freezes N+1. Core supplies
		// the exact end-block candidate and persists the same committee atomically
		// when the response requests preparation. T stays fixed at S + 3,600.
		if len(request.NextValidatorSet) == 0 || clock.CurrentEpoch == math.MaxUint64 || clock.ValidatorSetId == math.MaxUint64 {
			return &PluginEndResponse{Error: ErrState("epoch roster freeze is missing the next validator set")}
		}
		nextRecords, nextDeletes, snapshotErr := c.reconcileEpochValidatorSnapshot(clock.CurrentEpoch+1, request.NextValidatorSet)
		if snapshotErr != nil {
			return &PluginEndResponse{Error: snapshotErr}
		}
		for key, value := range nextRecords {
			records[key] = value
		}
		deletes = append(deletes, nextDeletes...)
		candidateHash, hashErr := validatorHandoffRosterHash(request.NextValidatorSet, c.Config.ChainId)
		if hashErr != nil {
			return &PluginEndResponse{Error: hashErr}
		}
		currentHash, hashErr := c.epochValidatorRosterHash(clock.CurrentEpoch)
		if hashErr != nil {
			return &PluginEndResponse{Error: hashErr}
		}
		rotationRequired := !bytes.Equal(currentHash, candidateHash)
		clock.ValidatorRosterFrozen = true
		clock.FreezeHeight = request.Height
		if rotationRequired {
			clock.ValidatorHandoffDomains = authorityHandoffDomains(params)
			if len(clock.ValidatorHandoffDomains) == 0 {
				return &PluginEndResponse{Error: ErrState("epoch handoff has no governed settlement domains")}
			}
			clock.ValidatorHandoffPrepared = true
			clock.ValidatorHandoffRosterHash = candidateHash
			clock.ValidatorHandoffDomainSetHash = validatorHandoffDomainSetHash(clock.ValidatorHandoffDomains)
			clock.ValidatorHandoffNativeChainId = c.Config.ChainId
			clock.ValidatorHandoffDomainCount = uint64(len(clock.ValidatorHandoffDomains))
			clock.ValidatorHandoffResolvedCount = 0
			handoffTimestamp := epochHandoffTimestamp
			if clock.ConsensusTimeSeconds > epochHandoffTimestamp-validatorMinimumHandoffNoticeSeconds {
				clock.FailedEpoch = true
			}
			handoffDeletes, startErr := startValidatorHandoffAt(clock, handoffTimestamp)
			if startErr != nil {
				return &PluginEndResponse{Error: startErr}
			}
			deletes = append(deletes, handoffDeletes...)
			manifest, manifestErr := c.buildValidatorHandoffManifest(clock, params, request.Height, request.NextValidatorSet)
			if manifestErr != nil {
				return &PluginEndResponse{Error: manifestErr}
			}
			records[string(KeyForValidatorHandoffManifest())] = manifest
			records[string(KeyForValidatorHandoffManifestRoot(manifest.Root))] = manifest
			return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{ValidatorSetEpochPrepare: true, Error: c.writeChanges(records, deletes)}, handoffAuxiliaryCandidate(manifest))
		}
		return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{ValidatorSetEpochPrepare: true, Error: c.writeChanges(records, deletes)})
	}
	rotationRequired := clock.ValidatorHandoffPrepared
	if rotationRequired {
		if handoffStateErr := validatePreparedValidatorHandoff(clock, c.Config.ChainId); handoffStateErr != nil {
			return &PluginEndResponse{Error: handoffStateErr}
		}
		ready, readyErr := c.validatorHandoffReady(clock)
		if readyErr != nil {
			return &PluginEndResponse{Error: readyErr}
		}
		if !ready || clock.ConsensusTimeSeconds < clock.ValidatorHandoffTimestamp {
			if clock.ConsensusTimeSeconds >= clock.ValidatorHandoffTimestamp {
				clock.FailedEpoch = true
			}
			priority, priorityErr := c.currentHandoffAuxiliaryCandidate(clock)
			if priorityErr != nil {
				return &PluginEndResponse{Error: priorityErr}
			}
			return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.writeChanges(records, deletes)}, priority)
		}
	} else if clock.ConsensusTimeSeconds < epochHandoffTimestamp {
		return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.writeChanges(records, deletes)})
	}
	// T, rather than a roster change, is the normal epoch boundary. A changed
	// roster reaches this point only after every frozen domain queue finalized.
	completedAt := epochHandoffTimestamp
	if rotationRequired {
		completedAt = clock.ValidatorHandoffTimestamp
	}
	if clock.ConsensusTimeSeconds > completedAt {
		completedAt = clock.ConsensusTimeSeconds
	}
	clock.EndHeight = request.Height
	if applyErr := c.snapshotCompletedEpoch(clock, params, records); applyErr != nil {
		return &PluginEndResponse{Error: applyErr}
	}
	if clock.CurrentEpoch == math.MaxUint64 || clock.ValidatorSetId == math.MaxUint64 || clock.EndHeight == math.MaxUint64 {
		return &PluginEndResponse{Error: ErrState("epoch clock overflow")}
	}
	clock.CurrentEpoch++
	if rotationRequired {
		clock.ValidatorSetId++
	}
	clock.StartHeight = clock.EndHeight + 1
	clock.EndHeight = 0
	clock.ValidatorHandoffPrepared = false
	clock.ValidatorRosterFrozen = false
	clock.ValidatorHandoffTimestamp = 0
	clock.ValidatorHandoffDomains = nil
	clock.ValidatorHandoffDomainCount = 0
	clock.ValidatorHandoffResolvedCount = 0
	clock.ValidatorHandoffRosterHash = nil
	clock.ValidatorHandoffDomainSetHash = nil
	clock.ValidatorHandoffOutgoingAuthorityCutoff = 0
	clock.ValidatorHandoffNativeChainId = 0
	clock.StartTimestamp = completedAt
	clock.FreezeTimestamp = completedAt + validatorEpochOpenSeconds
	clock.NominalEndTimestamp = completedAt + validatorEpochDurationSeconds
	clock.FreezeHeight = 0
	clock.FailedEpoch = false
	deletes = append(deletes, KeyForValidatorHandoffManifest())
	return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{ValidatorSetEpochEnd: true, Error: c.writeChanges(records, deletes)})
}

func validatorEpochPhaseTimes(clock *EpochClock) (uint64, uint64, *PluginError) {
	if clock == nil || clock.StartTimestamp == 0 || clock.FreezeTimestamp != clock.StartTimestamp+validatorEpochOpenSeconds ||
		clock.NominalEndTimestamp != clock.StartTimestamp+validatorEpochDurationSeconds {
		return 0, 0, ErrState("validator epoch timestamp overflow")
	}
	return clock.FreezeTimestamp, clock.NominalEndTimestamp, nil
}

func (c *Contract) withNativeAuxiliaryCandidates(height uint64, params *ProtocolParams, response *PluginEndResponse, priority ...*AuxiliaryCandidate) *PluginEndResponse {
	if response.Error != nil {
		return response
	}
	candidates, err := c.nativeAuxiliaryCandidates(height, params, priority...)
	if err != nil {
		response.Error = err
		return response
	}
	response.AuxiliaryCandidates = candidates
	response.ReplaceAuxiliaryCandidates = true
	return response
}

func (c *Contract) currentHandoffAuxiliaryCandidate(clock *EpochClock) (*AuxiliaryCandidate, *PluginError) {
	manifest := new(ValidatorHandoffManifest)
	if found, err := c.read(KeyForValidatorHandoffManifest(), manifest); err != nil {
		return nil, err
	} else if !found {
		return nil, ErrState("validator handoff manifest is unavailable")
	}
	return handoffAuxiliaryCandidate(manifest), nil
}

func handoffAuxiliaryCandidate(manifest *ValidatorHandoffManifest) *AuxiliaryCandidate {
	key := append(uint64Bytes(manifest.OldValidatorSetId), uint64Bytes(manifest.NewValidatorSetId)...)
	return &AuxiliaryCandidate{Kind: "validator-handoff", Key: key, Digest: append([]byte(nil), manifest.Root...), Payload: append([]byte(nil), manifest.Generation...)}
}

func (c *Contract) validatorHandoffReady(clock *EpochClock) (bool, *PluginError) {
	if clock.ValidatorHandoffDomainCount != uint64(len(clock.ValidatorHandoffDomains)) ||
		clock.ValidatorHandoffResolvedCount > clock.ValidatorHandoffDomainCount {
		return false, ErrState("validator handoff resolution counters are invalid")
	}
	return clock.ValidatorHandoffResolvedCount == clock.ValidatorHandoffDomainCount, nil
}

func (c *Contract) markValidatorHandoffResolved(clock *EpochClock, domainID, proofID []byte, records map[string]proto.Message) *PluginError {
	if clock == nil || !clock.ValidatorHandoffPrepared || !handoffIncludesDomain(clock, domainID) {
		return ErrConflict("validator handoff domain is not awaiting resolution")
	}
	key := KeyForRotationResolutionIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1)
	if _, staged := records[string(key)]; staged {
		return ErrConflict("validator handoff domain already has a finalized resolution")
	}
	if found, err := c.read(key, new(ReplayMarker)); err != nil {
		return err
	} else if found {
		return ErrConflict("validator handoff domain already has a finalized resolution")
	}
	if clock.ValidatorHandoffResolvedCount >= clock.ValidatorHandoffDomainCount {
		return ErrState("validator handoff resolution counter overflow")
	}
	clock.ValidatorHandoffResolvedCount++
	records[string(key)] = &ReplayMarker{Id: append([]byte(nil), proofID...)}
	records[string(KeyForEpochClock())] = clock
	return nil
}

func validatorHandoffGeneration(clock *EpochClock) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("takusen:validator-handoff-generation:v2"))
	_, _ = hash.Write(uint64Bytes(clock.ValidatorHandoffNativeChainId))
	_, _ = hash.Write(uint64Bytes(clock.CurrentEpoch))
	_, _ = hash.Write(uint64Bytes(clock.ValidatorSetId))
	_, _ = hash.Write(uint64Bytes(clock.ValidatorSetId + 1))
	_, _ = hash.Write(clock.ValidatorHandoffRosterHash)
	_, _ = hash.Write(clock.ValidatorHandoffDomainSetHash)
	_, _ = hash.Write(uint64Bytes(clock.ValidatorHandoffTimestamp))
	_, _ = hash.Write(uint64Bytes(clock.ValidatorHandoffOutgoingAuthorityCutoff))
	return hash.Sum(nil)
}

func validatorHandoffDomainSetHash(domains [][]byte) []byte {
	ordered := make([][]byte, len(domains))
	for index, domain := range domains {
		ordered[index] = append([]byte(nil), domain...)
	}
	sort.Slice(ordered, func(i, j int) bool { return bytes.Compare(ordered[i], ordered[j]) < 0 })
	hash := sha256.New()
	_, _ = hash.Write([]byte("takusen:validator-handoff-domains:v1"))
	_, _ = hash.Write(uint64Bytes(uint64(len(ordered))))
	for _, domain := range ordered {
		_, _ = hash.Write(domain)
	}
	return hash.Sum(nil)
}

func validatorHandoffRosterHash(encoded []byte, chainID uint64) ([]byte, *PluginError) {
	decoded, err := decodeActiveValidatorSet(encoded, chainID)
	if err != nil {
		return nil, err
	}
	validators := make([]*Validator, 0, len(decoded))
	for _, value := range decoded {
		validators = append(validators, value.(*Validator))
	}
	return validatorRosterHash(validators), nil
}

func validatorRosterHash(validators []*Validator) []byte {
	sortValidatorsByConsensusOrder(validators)
	hash := sha256.New()
	_, _ = hash.Write([]byte("takusen:validator-handoff-roster:v1"))
	_, _ = hash.Write(uint64Bytes(uint64(len(validators))))
	for _, validator := range validators {
		keyHash := sha256.Sum256(validator.PublicKey)
		_, _ = hash.Write(keyHash[:])
		_, _ = hash.Write(uint64Bytes(validator.StakedAmount))
	}
	return hash.Sum(nil)
}

func (c *Contract) epochValidatorRosterHash(epoch uint64) ([]byte, *PluginError) {
	entries, err := c.rangeRead(EpochValidatorPrefix(epoch))
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, ErrState("epoch validator snapshot is empty")
	}
	validators := make([]*Validator, 0, len(entries))
	for _, entry := range entries {
		validator := new(Validator)
		if decodeErr := Unmarshal(entry.Value, validator); decodeErr != nil {
			return nil, decodeErr
		}
		validators = append(validators, validator)
	}
	return validatorRosterHash(validators), nil
}

func validatePreparedValidatorHandoff(clock *EpochClock, chainID uint64) *PluginError {
	if clock == nil || !clock.ValidatorRosterFrozen || !clock.ValidatorHandoffPrepared ||
		clock.ValidatorHandoffTimestamp == 0 || clock.ValidatorHandoffOutgoingAuthorityCutoff == 0 ||
		clock.ValidatorHandoffNativeChainId != chainID || len(clock.ValidatorHandoffRosterHash) != 32 ||
		len(clock.ValidatorHandoffDomainSetHash) != 32 || len(clock.ValidatorHandoffDomains) == 0 ||
		clock.ValidatorHandoffDomainCount != uint64(len(clock.ValidatorHandoffDomains)) ||
		clock.ValidatorHandoffResolvedCount > clock.ValidatorHandoffDomainCount ||
		!bytes.Equal(clock.ValidatorHandoffDomainSetHash, validatorHandoffDomainSetHash(clock.ValidatorHandoffDomains)) {
		return ErrState("validator handoff state is invalid")
	}
	return nil
}

// authorityHandoffDomains includes every governed custody/verifier domain.
// Active controls user traffic only; it never permits stale validator
// authority to survive on a staged or temporarily disabled EVM deployment.
func authorityHandoffDomains(params *ProtocolParams) [][]byte {
	domains := make([][]byte, 0, len(params.SettlementDomains))
	for _, domain := range params.SettlementDomains {
		if domain != nil && len(domain.Id) == 32 {
			domains = append(domains, append([]byte(nil), domain.Id...))
		}
	}
	sort.Slice(domains, func(i, j int) bool { return bytes.Compare(domains[i], domains[j]) < 0 })
	return domains
}

func handoffIncludesDomain(clock *EpochClock, domainID []byte) bool {
	if clock == nil || len(domainID) != 32 {
		return false
	}
	for _, candidate := range clock.ValidatorHandoffDomains {
		if bytes.Equal(candidate, domainID) {
			return true
		}
	}
	return false
}

func (c *Contract) currentEpochClockFromState() (*EpochClock, *PluginError) {
	params, err := c.currentProtocolParams()
	if err != nil {
		return nil, err
	}
	return c.currentEpochClock(params)
}

func startValidatorHandoffAt(clock *EpochClock, handoffTimestamp uint64) ([][]byte, *PluginError) {
	if clock == nil || handoffTimestamp == 0 || (!clock.FailedEpoch &&
		(handoffTimestamp <= clock.ConsensusTimeSeconds || handoffTimestamp-clock.ConsensusTimeSeconds < validatorMinimumHandoffNoticeSeconds)) {
		return nil, ErrState("validator handoff timestamp is invalid")
	}
	clock.ValidatorHandoffTimestamp = handoffTimestamp
	clock.ValidatorHandoffOutgoingAuthorityCutoff = clock.ValidatorHandoffTimestamp
	deletes := make([][]byte, 0, len(clock.ValidatorHandoffDomains)*3)
	for _, domainID := range clock.ValidatorHandoffDomains {
		deletes = append(deletes,
			KeyForRotationProofIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1),
			KeyForQueuedRotationIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1),
			KeyForRotationResolutionIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1),
		)
	}
	return deletes, nil
}

func (c *Contract) currentEpochClock(params *ProtocolParams) (*EpochClock, *PluginError) {
	clock := new(EpochClock)
	if found, err := c.read(KeyForEpochClock(), clock); err != nil {
		return nil, err
	} else if found {
		if clock.CurrentEpoch == 0 || clock.StartHeight == 0 || clock.ValidatorSetId == 0 ||
			(clock.EndHeight != 0 && clock.EndHeight < clock.StartHeight) {
			return nil, ErrState("invalid epoch clock")
		}
		if clock.StartTimestamp == 0 {
			if clock.CurrentEpoch != 1 || clock.ConsensusTimeSeconds != 0 || clock.FreezeTimestamp != 0 || clock.NominalEndTimestamp != 0 {
				return nil, ErrState("invalid unstarted epoch clock")
			}
		} else if clock.ConsensusTimeSeconds < clock.StartTimestamp ||
			clock.FreezeTimestamp != clock.StartTimestamp+validatorEpochOpenSeconds ||
			clock.NominalEndTimestamp != clock.StartTimestamp+validatorEpochDurationSeconds {
			return nil, ErrState("invalid epoch time schedule")
		}
		if !clock.ValidatorHandoffPrepared && (clock.ValidatorHandoffTimestamp != 0 || len(clock.ValidatorHandoffDomains) != 0 ||
			len(clock.ValidatorHandoffRosterHash) != 0 ||
			len(clock.ValidatorHandoffDomainSetHash) != 0 || clock.ValidatorHandoffOutgoingAuthorityCutoff != 0 ||
			clock.ValidatorHandoffNativeChainId != 0 || clock.ValidatorHandoffDomainCount != 0 ||
			clock.ValidatorHandoffResolvedCount != 0) {
			return nil, ErrState("validator epoch contains incomplete handoff state")
		}
		if !clock.ValidatorRosterFrozen && clock.ValidatorHandoffPrepared {
			return nil, ErrState("unfrozen validator epoch contains a prepared handoff")
		}
		if clock.ValidatorRosterFrozen {
			if clock.CurrentEpoch == math.MaxUint64 {
				return nil, ErrState("epoch counter overflow")
			}
			frozenRosterHash, err := c.epochValidatorRosterHash(clock.CurrentEpoch + 1)
			if err != nil {
				return nil, err
			}
			if clock.ValidatorHandoffPrepared && !bytes.Equal(frozenRosterHash, clock.ValidatorHandoffRosterHash) {
				return nil, ErrState("validator handoff roster commitment does not match the frozen snapshot")
			}
		}
		if clock.ValidatorHandoffPrepared {
			if err := validatePreparedValidatorHandoff(clock, c.Config.ChainId); err != nil {
				return nil, err
			}
		}
		return clock, nil
	}
	if found, readErr := c.read(KeyForLatestEpoch(), new(ReplayMarker)); readErr != nil {
		return nil, readErr
	} else if found {
		return nil, ErrState("epoch clock initialization requires fresh state")
	}
	if authorizations, readErr := c.rangeRead(EpochAuthorizationPrefix()); readErr != nil {
		return nil, readErr
	} else if len(authorizations) != 0 {
		return nil, ErrState("epoch clock initialization requires fresh state")
	}
	return &EpochClock{CurrentEpoch: 1, StartHeight: 1, ValidatorSetId: 1}, nil
}

func (c *Contract) currentValidatorSetID(params *ProtocolParams) (uint64, *PluginError) {
	clock, err := c.currentEpochClock(params)
	if err != nil {
		return 0, err
	}
	return clock.ValidatorSetId, nil
}

func (c *Contract) snapshotCompletedEpoch(clock *EpochClock, params *ProtocolParams, records map[string]proto.Message) *PluginError {
	epoch, height := clock.CurrentEpoch, clock.EndHeight
	if found, err := c.read(KeyForEpochAuthorization(epoch), new(EpochAuthorization)); err != nil {
		return err
	} else if found {
		return ErrConflict("epoch authorization already exists")
	}
	records[string(KeyForEpochAuthorization(epoch))] = &EpochAuthorization{
		Epoch: epoch, StartHeight: clock.StartHeight, EndHeight: height,
		ValidatorSetId: clock.ValidatorSetId, Status: "accounting_pending",
	}
	records[string(KeyForLatestEpoch())] = &ReplayMarker{Id: uint64Bytes(epoch)}
	records[string(KeyForPendingEpochAccounting(epoch))] = &EpochAccountingJob{
		Epoch: epoch, EmissionPerEpoch: params.EmissionPerEpoch,
		TreasuryAddress: append([]byte(nil), params.TreasuryAddress...), TreasuryBps: params.TreasuryBps,
		CanonicalChainId: params.CanonicalChainId, CanonicalTokenAddress: append([]byte(nil), params.CanonicalTokenAddress...),
	}
	return nil
}

func (c *Contract) processPendingEpochAccounting(records map[string]proto.Message) ([][]byte, *PluginError) {
	deletes := make([][]byte, 0)
	entries, err := c.rangeReadPage(PendingEpochAccountingPrefix(), nil, 1)
	if err != nil {
		return nil, err
	}
	if len(entries) != 0 {
		job := new(EpochAccountingJob)
		if decodeErr := Unmarshal(entries[0].Value, job); decodeErr != nil || job.Epoch == 0 {
			return nil, ErrState("pending epoch accounting index is invalid")
		}
		params := &ProtocolParams{
			EmissionPerEpoch: job.EmissionPerEpoch, TreasuryAddress: append([]byte(nil), job.TreasuryAddress...), TreasuryBps: job.TreasuryBps,
			CanonicalChainId: job.CanonicalChainId, CanonicalTokenAddress: append([]byte(nil), job.CanonicalTokenAddress...),
		}
		if accountingErr := c.finalizeEpochRewards(job.Epoch, params, records); accountingErr != nil {
			return nil, accountingErr
		}
		deletes = append(deletes, append([]byte(nil), entries[0].Key...))
	}
	return deletes, nil
}

func (c *Contract) finalizeEpochRewards(epoch uint64, params *ProtocolParams, records map[string]proto.Message) *PluginError {
	authorization := new(EpochAuthorization)
	if found, err := c.read(KeyForEpochAuthorization(epoch), authorization); err != nil {
		return err
	} else if !found {
		return ErrState("pending epoch accounting snapshot is unavailable")
	}
	if authorization.Status != "accounting_pending" {
		return nil
	}
	entries, err := c.rangeReadPage(ProducerPrefix(epoch), nil, maxValidatorSetSize+1)
	if err != nil {
		return err
	}
	if len(entries) > maxValidatorSetSize {
		return ErrState("epoch producer snapshot exceeds the validator limit")
	}
	producers := make(map[string]*ProducerRecord, len(entries))
	for _, entry := range entries {
		record := new(ProducerRecord)
		if decodeErr := Unmarshal(entry.Value, record); decodeErr != nil {
			return decodeErr
		}
		producers[string(record.ProducerAddress)] = record
	}
	ordered := make([]*ProducerRecord, 0, len(producers))
	var totalBlocks uint64
	for _, record := range producers {
		if ^uint64(0)-totalBlocks < record.Blocks {
			return ErrState("epoch producer accounting overflow")
		}
		totalBlocks += record.Blocks
		ordered = append(ordered, record)
	}
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i].ProducerAddress, ordered[j].ProducerAddress) < 0
	})
	authorization.Status = "authorized"
	if params.EmissionPerEpoch == 0 || totalBlocks == 0 {
		authorization.Status = "emission_disabled"
		records[string(KeyForEpochAuthorization(epoch))] = authorization
		return nil
	}
	treasury, validTreasury := mulDiv64(params.EmissionPerEpoch, uint64(params.TreasuryBps), 10_000)
	if !validTreasury {
		return ErrState("epoch treasury calculation overflow")
	}
	producerTotal := params.EmissionPerEpoch - treasury
	remaining := producerTotal
	recipients := make([][]byte, 0, len(ordered)+1)
	amounts := make([]uint64, 0, len(ordered)+1)
	for index, record := range ordered {
		amount, validAmount := mulDiv64(producerTotal, record.Blocks, totalBlocks)
		if !validAmount {
			return ErrState("epoch reward calculation overflow")
		}
		if index == len(ordered)-1 {
			amount = remaining
		} else {
			remaining -= amount
		}
		payout := append([]byte(nil), record.ProducerAddress...)
		configured := new(ProducerPayout)
		if found, readErr := c.read(KeyForProducerPayout(record.ProducerAddress), configured); readErr != nil {
			return readErr
		} else if found {
			payout = append([]byte(nil), configured.CanonicalChainAddress...)
		}
		allocation := &RewardAllocation{
			ProducerAddress: append([]byte(nil), record.ProducerAddress...), CanonicalChainRecipient: payout,
			Blocks: record.Blocks, Amount: amount,
		}
		if amount != 0 {
			recipients, amounts = append(recipients, payout), append(amounts, amount)
		}
		authorization.Allocations = append(authorization.Allocations, allocation)
	}
	if treasury != 0 {
		if !validAddress(params.TreasuryAddress) {
			return ErrState("epoch treasury address is unavailable")
		}
		recipients, amounts = append(recipients, append([]byte(nil), params.TreasuryAddress...)), append(amounts, treasury)
	}
	authorization.TreasuryAddress = append([]byte(nil), params.TreasuryAddress...)
	authorization.TreasuryAmount = treasury
	authorization.ProducerAmount = producerTotal
	authorization.TotalAmount = authorization.ProducerAmount + treasury
	if authorization.TotalAmount != 0 {
		authorization.CanonicalChainDigest = epochAuthorizationDigest(params, authorization.ValidatorSetId, epoch, recipients, amounts)
		records[string(KeyForPendingEpochAuthorization(epoch))] = &ReplayMarker{Id: uint64Bytes(epoch)}
	}
	records[string(KeyForEpochAuthorization(epoch))] = authorization
	return nil
}

func (c *Contract) deliverObserveEpochMint(height uint64, message *MessageObserveEpochMint) *PluginDeliverResponse {
	return c.deliverObserveEpochMintCertified(height, message, false)
}

func (c *Contract) deliverObserveEpochMintCertified(height uint64, message *MessageObserveEpochMint, certified bool) *PluginDeliverResponse {
	authorization := new(EpochAuthorization)
	if found, err := c.read(KeyForEpochAuthorization(message.Epoch), authorization); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || authorization.Status != "authorized" {
		return &PluginDeliverResponse{Error: ErrConflict("epoch reward authorization is not pending")}
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	currentSetID, setErr := c.currentValidatorSetID(params)
	if setErr != nil {
		return &PluginDeliverResponse{Error: setErr}
	}
	if !certified && message.ValidatorSetId != currentSetID {
		return &PluginDeliverResponse{Error: ErrUnauthorized("epoch mint does not use the current validator set")}
	}
	subject := hashFields([]byte("takusen:epoch-mint"), uint64Bytes(message.Epoch), message.CanonicalChainTxHash, uint64Bytes(message.ValidatorSetId))
	claim := hashFields([]byte("epoch-mint"), uint64Bytes(message.Epoch))
	reached := certified
	records := make(map[string]proto.Message)
	if !certified {
		observation, observed, observeErr := c.observe(observationEpochMint, subject, claim, message.ObserverAddress, height)
		if observeErr != nil {
			return &PluginDeliverResponse{Error: observeErr}
		}
		reached = observed
		records = observationRecords(observationEpochMint, subject, claim, message.ObserverAddress, observation)
	}
	if reached {
		authorization.Status = "minted"
		authorization.CanonicalChainMintTxHash = append([]byte(nil), message.CanonicalChainTxHash...)
		records[string(KeyForEpochAuthorization(message.Epoch))] = authorization
		return &PluginDeliverResponse{Error: c.writeChanges(records, [][]byte{KeyForPendingEpochAuthorization(message.Epoch)})}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func epochAuthorizationDigest(params *ProtocolParams, validatorSetID, epoch uint64, recipients [][]byte, amounts []uint64) []byte {
	recipientsHash := keccak256(abiAddressArray(recipients))
	amountsHash := keccak256(abiUint64Array(amounts))
	encoded := make([]byte, 0, 32*7)
	encoded = append(encoded, keccak256([]byte(epochRewardsType))...)
	encoded = append(encoded, abiUint64(params.CanonicalChainId)...)
	encoded = append(encoded, abiAddress(params.CanonicalTokenAddress)...)
	encoded = append(encoded, abiUint64(validatorSetID)...)
	encoded = append(encoded, abiUint64(epoch)...)
	encoded = append(encoded, recipientsHash...)
	encoded = append(encoded, amountsHash...)
	return keccak256(encoded)
}

func abiAddressArray(values [][]byte) []byte {
	encoded := make([]byte, 0, 64+32*len(values))
	encoded = append(encoded, abiUint64(32)...)
	encoded = append(encoded, abiUint64(uint64(len(values)))...)
	for _, value := range values {
		encoded = append(encoded, abiAddress(value)...)
	}
	return encoded
}

func abiUint64Array(values []uint64) []byte {
	encoded := make([]byte, 0, 64+32*len(values))
	encoded = append(encoded, abiUint64(32)...)
	encoded = append(encoded, abiUint64(uint64(len(values)))...)
	for _, value := range values {
		encoded = append(encoded, abiUint64(value)...)
	}
	return encoded
}
