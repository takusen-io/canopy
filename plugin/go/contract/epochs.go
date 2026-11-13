package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"

	"google.golang.org/protobuf/proto"
)

const epochRewardsType = "EpochRewards(uint256 chainId,address token,uint64 validatorSetId,uint64 epoch,bytes32 recipientsHash,bytes32 amountsHash)"
const maxEpochSlashApplications uint64 = 256
const validatorHandoffAbortLeadSeconds uint64 = 1_200

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
	if request.Height < clock.StartHeight || request.Height > clock.EndHeight {
		return &PluginEndResponse{Error: ErrState("block height is outside the current epoch")}
	}
	clock.ConsensusTimeSeconds = request.TimeMicros / 1_000_000
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
	if request.Height != clock.EndHeight {
		return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.write(records)})
	}
	var deletes [][]byte
	rotationRequired := clock.ValidatorHandoffPrepared
	if !clock.ValidatorHandoffPrepared {
		// The nominal boundary is the only place where N+1, the governed domain
		// set, and handoff parameters are frozen. Core supplies the exact
		// end-block candidate and persists the same committee atomically when the
		// response requests preparation.
		if len(request.NextValidatorSet) == 0 || clock.CurrentEpoch == math.MaxUint64 || clock.ValidatorSetId == math.MaxUint64 {
			return &PluginEndResponse{Error: ErrState("epoch boundary is missing the next validator set")}
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
		rotationRequired = !bytes.Equal(currentHash, candidateHash)
		if rotationRequired {
			clock.ValidatorHandoffDomains = authorityHandoffDomains(params)
			if len(clock.ValidatorHandoffDomains) == 0 {
				return &PluginEndResponse{Error: ErrState("epoch handoff has no governed settlement domains")}
			}
			clock.ValidatorHandoffPrepared = true
			clock.ValidatorHandoffNoticeSeconds = params.ValidatorHandoffNoticeSeconds
			clock.ValidatorHandoffRosterHash = candidateHash
			clock.ValidatorHandoffDomainSetHash = validatorHandoffDomainSetHash(clock.ValidatorHandoffDomains)
			clock.ValidatorHandoffNativeChainId = c.Config.ChainId
			attemptDeletes, startErr := startValidatorHandoffAttempt(clock)
			if startErr != nil {
				return &PluginEndResponse{Error: startErr}
			}
			deletes = append(deletes, attemptDeletes...)
			manifest, manifestErr := c.buildValidatorHandoffManifest(clock, params, request.Height, request.NextValidatorSet)
			if manifestErr != nil {
				return &PluginEndResponse{Error: manifestErr}
			}
			records[string(KeyForValidatorHandoffManifest())] = manifest
			records[string(KeyForValidatorHandoffManifestRoot(manifest.Root))] = manifest
			if clock.EndHeight == math.MaxUint64 {
				return &PluginEndResponse{Error: ErrState("epoch handoff wait overflow")}
			}
			clock.EndHeight++
			return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{ValidatorSetEpochPrepare: true, Error: c.writeChanges(records, deletes)}, handoffAuxiliaryCandidate(manifest))
		}
	}
	if rotationRequired {
		if handoffStateErr := validatePreparedValidatorHandoff(clock, c.Config.ChainId); handoffStateErr != nil {
			return &PluginEndResponse{Error: handoffStateErr}
		}
		ready, readyErr := c.validatorHandoffReady(clock)
		if readyErr != nil {
			return &PluginEndResponse{Error: readyErr}
		}
		if clock.ValidatorHandoffCancelling {
			cancelled, cancelErr := c.validatorHandoffCancellationReady(clock)
			if cancelErr != nil {
				return &PluginEndResponse{Error: cancelErr}
			}
			// A finalized cancellation event can only have been produced before T.
			// Native certification may arrive later, but the complete snapshotted
			// domain evidence still proves that no domain switched authority.
			if cancelled {
				attemptDeletes, startErr := startValidatorHandoffAttempt(clock)
				if startErr != nil {
					return &PluginEndResponse{Error: startErr}
				}
				deletes = append(deletes, attemptDeletes...)
				clock.ValidatorHandoffCancelling = false
				if clock.EndHeight == math.MaxUint64 {
					return &PluginEndResponse{Error: ErrState("epoch handoff retry overflow")}
				}
				manifest, manifestErr := c.buildValidatorHandoffManifest(clock, params, request.Height, nil)
				if manifestErr != nil {
					return &PluginEndResponse{Error: manifestErr}
				}
				records[string(KeyForValidatorHandoffManifest())] = manifest
				records[string(KeyForValidatorHandoffManifestRoot(manifest.Root))] = manifest
				clock.EndHeight++
				return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.writeChanges(records, deletes)}, handoffAuxiliaryCandidate(manifest))
			}
			if clock.EndHeight == math.MaxUint64 {
				return &PluginEndResponse{Error: ErrState("epoch handoff cancellation wait overflow")}
			}
			clock.EndHeight++
			priority, priorityErr := c.currentHandoffAuxiliaryCandidate(clock)
			if priorityErr != nil {
				return &PluginEndResponse{Error: priorityErr}
			}
			return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.write(records)}, priority)
		}
		if !ready || clock.ConsensusTimeSeconds < clock.ValidatorHandoffTimestamp {
			if !ready && handoffCancellationWindowOpen(clock) {
				handoff := new(ValidatorHandoffManifest)
				if found, readErr := c.read(KeyForValidatorHandoffManifest(), handoff); readErr != nil {
					return &PluginEndResponse{Error: readErr}
				} else if !found {
					return &PluginEndResponse{Error: ErrState("validator handoff manifest is unavailable")}
				}
				manifest, manifestErr := buildValidatorHandoffCancellationManifest(handoff, request.Height)
				if manifestErr != nil {
					return &PluginEndResponse{Error: manifestErr}
				}
				clock.ValidatorHandoffCancelling = true
				records[string(KeyForValidatorHandoffCancellationManifest())] = manifest
				records[string(KeyForValidatorHandoffCancellationManifestRoot(manifest.Root))] = manifest
				if clock.EndHeight == math.MaxUint64 {
					return &PluginEndResponse{Error: ErrState("epoch handoff cancellation wait overflow")}
				}
				clock.EndHeight++
				return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.write(records)}, handoffCancellationAuxiliaryCandidate(manifest))
			}
			if clock.EndHeight == math.MaxUint64 {
				return &PluginEndResponse{Error: ErrState("epoch handoff wait overflow")}
			}
			// Fail closed while retaining the old committee. The precommitted next
			// snapshot and late stake changes remain untouched.
			clock.EndHeight++
			priority, priorityErr := c.currentHandoffAuxiliaryCandidate(clock)
			if priorityErr != nil {
				return &PluginEndResponse{Error: priorityErr}
			}
			return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.write(records)}, priority)
		}
	}
	stakeDeletes, applyErr := c.applyEpochStakeChanges(epoch, params, records)
	if applyErr != nil {
		return &PluginEndResponse{Error: applyErr}
	}
	deletes = append(deletes, stakeDeletes...)
	slashDeletes, slashesComplete, applyErr := c.applyEpochSlashes(epoch, params, records, maxEpochSlashApplications)
	if applyErr != nil {
		return &PluginEndResponse{Error: applyErr}
	}
	deletes = append(deletes, slashDeletes...)
	if !slashesComplete {
		if clock.EndHeight == math.MaxUint64 {
			return &PluginEndResponse{Error: ErrState("epoch slash queue overflow")}
		}
		// Bound end-block consensus work. Persist this chunk and extend the same
		// epoch by one block; the next boundary continues the pending index.
		clock.EndHeight++
		return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{Error: c.writeChanges(records, deletes)})
	}
	if applyErr = c.finalizeEpoch(clock, request.ProposerAddress, producer, params, records); applyErr != nil {
		return &PluginEndResponse{Error: applyErr}
	}
	if clock.CurrentEpoch == math.MaxUint64 || clock.ValidatorSetId == math.MaxUint64 ||
		params.EpochBlocks == 0 || clock.EndHeight == math.MaxUint64 ||
		clock.EndHeight+1 > math.MaxUint64-(params.EpochBlocks-1) {
		return &PluginEndResponse{Error: ErrState("epoch clock overflow")}
	}
	clock.CurrentEpoch++
	if rotationRequired {
		clock.ValidatorSetId++
	}
	clock.StartHeight = clock.EndHeight + 1
	clock.EpochBlocks = params.EpochBlocks
	clock.ValidatorHandoffPrepared = false
	clock.ValidatorHandoffTimestamp = 0
	clock.ValidatorHandoffDomains = nil
	clock.ValidatorHandoffAttempt = 0
	clock.ValidatorHandoffRosterHash = nil
	clock.ValidatorHandoffDomainSetHash = nil
	clock.ValidatorHandoffOutgoingAuthorityCutoff = 0
	clock.ValidatorHandoffNativeChainId = 0
	clock.ValidatorHandoffCancelling = false
	deletes = append(deletes, KeyForValidatorHandoffManifest())
	deletes = append(deletes, KeyForValidatorHandoffCancellationManifest())
	clock.EndHeight = clock.StartHeight + params.EpochBlocks - 1
	return c.withNativeAuxiliaryCandidates(request.Height, params, &PluginEndResponse{ValidatorSetEpochEnd: true, Error: c.writeChanges(records, deletes)})
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
	if clock.ValidatorHandoffCancelling {
		manifest := new(ValidatorHandoffCancellationManifest)
		if found, err := c.read(KeyForValidatorHandoffCancellationManifest(), manifest); err != nil {
			return nil, err
		} else if !found {
			return nil, ErrState("validator handoff cancellation manifest is unavailable")
		}
		return handoffCancellationAuxiliaryCandidate(manifest), nil
	}
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
	key = append(key, uint64Bytes(manifest.Attempt)...)
	return &AuxiliaryCandidate{Kind: "validator-handoff", Key: key, Digest: append([]byte(nil), manifest.Root...), Payload: append([]byte(nil), manifest.Generation...)}
}

func handoffCancellationAuxiliaryCandidate(manifest *ValidatorHandoffCancellationManifest) *AuxiliaryCandidate {
	key := append(uint64Bytes(manifest.OldValidatorSetId), uint64Bytes(manifest.NewValidatorSetId)...)
	key = append(key, manifest.HandoffGeneration...)
	return &AuxiliaryCandidate{Kind: "validator-handoff-cancellation", Key: key, Digest: append([]byte(nil), manifest.Root...), Payload: append([]byte(nil), manifest.HandoffGeneration...)}
}

func (c *Contract) validatorHandoffReady(clock *EpochClock) (bool, *PluginError) {
	expectedGeneration := validatorHandoffGeneration(clock)
	for _, domainID := range clock.ValidatorHandoffDomains {
		if len(domainID) != 32 {
			return false, ErrState("validator handoff domain snapshot is invalid")
		}
		if found, readErr := c.read(KeyForRotationCancellationIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1), new(ReplayMarker)); readErr != nil {
			return false, readErr
		} else if found {
			return false, nil
		}
		marker := new(ReplayMarker)
		if found, readErr := c.read(KeyForQueuedRotationIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1), marker); readErr != nil {
			return false, readErr
		} else if !found {
			return false, nil
		}
		proof := new(QuorumProof)
		if found, readErr := c.read(KeyForQuorumProof(marker.Id), proof); readErr != nil {
			return false, readErr
		} else if !found || proof.ProofKind != "validator-set-rotation-queued" || proof.ValidatorSetId != clock.ValidatorSetId ||
			proof.NewValidatorSetId != clock.ValidatorSetId+1 || proof.CompletedHeight == 0 ||
			!bytes.Equal(proof.HandoffGeneration, expectedGeneration) || proof.HandoffTimestamp != clock.ValidatorHandoffTimestamp ||
			!bytes.Equal(proof.SettlementDomainId, domainID) {
			return false, ErrState("validator rotation schedule index references an invalid proof")
		}
	}
	return true, nil
}

func (c *Contract) validatorHandoffCancellationReady(clock *EpochClock) (bool, *PluginError) {
	expectedGeneration := validatorHandoffGeneration(clock)
	for _, domainID := range clock.ValidatorHandoffDomains {
		marker := new(ReplayMarker)
		found, err := c.read(KeyForRotationResolutionIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1), marker)
		if err != nil {
			return false, err
		}
		if !found {
			return false, nil
		}
		proof := new(QuorumProof)
		found, err = c.read(KeyForQuorumProof(marker.Id), proof)
		if err != nil {
			return false, err
		}
		if !found || (proof.ProofKind != "validator-set-rotation-cancelled" && proof.ProofKind != "validator-set-rotation-absent") ||
			proof.ValidatorSetId != clock.ValidatorSetId || proof.NewValidatorSetId != clock.ValidatorSetId+1 ||
			!bytes.Equal(proof.SettlementDomainId, domainID) || !bytes.Equal(proof.HandoffGeneration, expectedGeneration) ||
			proof.HandoffTimestamp != clock.ValidatorHandoffTimestamp {
			return false, ErrState("validator handoff resolution index references an invalid proof")
		}
	}
	return true, nil
}

func validatorHandoffGeneration(clock *EpochClock) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte("takusen:validator-handoff-generation:v1"))
	_, _ = hash.Write(uint64Bytes(clock.ValidatorHandoffNativeChainId))
	_, _ = hash.Write(uint64Bytes(clock.CurrentEpoch))
	_, _ = hash.Write(uint64Bytes(clock.ValidatorSetId))
	_, _ = hash.Write(uint64Bytes(clock.ValidatorSetId + 1))
	_, _ = hash.Write(clock.ValidatorHandoffRosterHash)
	_, _ = hash.Write(clock.ValidatorHandoffDomainSetHash)
	_, _ = hash.Write(uint64Bytes(clock.ValidatorHandoffAttempt))
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
	if clock == nil || !clock.ValidatorHandoffPrepared || clock.ValidatorHandoffAttempt == 0 ||
		clock.ValidatorHandoffTimestamp == 0 || clock.ValidatorHandoffOutgoingAuthorityCutoff == 0 ||
		clock.ValidatorHandoffNativeChainId != chainID || len(clock.ValidatorHandoffRosterHash) != 32 ||
		len(clock.ValidatorHandoffDomainSetHash) != 32 || len(clock.ValidatorHandoffDomains) == 0 ||
		!bytes.Equal(clock.ValidatorHandoffDomainSetHash, validatorHandoffDomainSetHash(clock.ValidatorHandoffDomains)) {
		return ErrState("validator handoff state is invalid or requires a boundary migration")
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

func handoffCancellationWindowOpen(clock *EpochClock) bool {
	return clock.ValidatorHandoffTimestamp > clock.ConsensusTimeSeconds &&
		clock.ValidatorHandoffTimestamp-clock.ConsensusTimeSeconds <= validatorHandoffAbortLeadSeconds
}

func startValidatorHandoffAttempt(clock *EpochClock) ([][]byte, *PluginError) {
	if clock.ValidatorHandoffNoticeSeconds < 1200 ||
		clock.ConsensusTimeSeconds > math.MaxUint64-clock.ValidatorHandoffNoticeSeconds ||
		clock.ValidatorHandoffAttempt == math.MaxUint64 {
		return nil, ErrState("validator handoff notice is invalid")
	}
	clock.ValidatorHandoffAttempt++
	clock.ValidatorHandoffTimestamp = clock.ConsensusTimeSeconds + clock.ValidatorHandoffNoticeSeconds
	clock.ValidatorHandoffOutgoingAuthorityCutoff = clock.ValidatorHandoffTimestamp
	deletes := make([][]byte, 0, len(clock.ValidatorHandoffDomains)*4)
	for _, domainID := range clock.ValidatorHandoffDomains {
		deletes = append(deletes,
			KeyForRotationProofIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1),
			KeyForQueuedRotationIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1),
			KeyForRotationCancellationIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1),
			KeyForRotationResolutionIndex(domainID, clock.ValidatorSetId, clock.ValidatorSetId+1),
		)
	}
	return deletes, nil
}

// validatorRotationRequired compares the exact core-frozen weighted rosters.
// Epochs that only advance accounting do not manufacture a new EVM authority
// generation and therefore need no cross-domain handoff ceremony.
func (c *Contract) validatorRotationRequired(clock *EpochClock) (bool, *PluginError) {
	current, err := c.rangeRead(EpochValidatorPrefix(clock.CurrentEpoch))
	if err != nil {
		return false, err
	}
	next, err := c.rangeRead(EpochValidatorPrefix(clock.CurrentEpoch + 1))
	if err != nil {
		return false, err
	}
	if len(current) == 0 || len(next) == 0 {
		// Legacy/bootstrap state without both snapshots conservatively follows
		// the rotating path. A production prepared epoch always has both.
		return true, nil
	}
	if len(current) != len(next) {
		return true, nil
	}
	type member struct {
		key    string
		weight uint64
	}
	decode := func(entries []*PluginStateEntry) ([]member, *PluginError) {
		members := make([]member, len(entries))
		for i, entry := range entries {
			validator := new(Validator)
			if decodeErr := Unmarshal(entry.Value, validator); decodeErr != nil {
				return nil, decodeErr
			}
			members[i] = member{key: string(validator.PublicKey), weight: validator.StakedAmount}
		}
		sort.Slice(members, func(i, j int) bool { return members[i].key < members[j].key })
		return members, nil
	}
	currentMembers, decodeErr := decode(current)
	if decodeErr != nil {
		return false, decodeErr
	}
	nextMembers, decodeErr := decode(next)
	if decodeErr != nil {
		return false, decodeErr
	}
	for i := range currentMembers {
		if currentMembers[i] != nextMembers[i] {
			return true, nil
		}
	}
	return false, nil
}

func (c *Contract) currentEpochClock(params *ProtocolParams) (*EpochClock, *PluginError) {
	clock := new(EpochClock)
	if found, err := c.read(KeyForEpochClock(), clock); err != nil {
		return nil, err
	} else if found {
		if clock.CurrentEpoch == 0 || clock.StartHeight == 0 || clock.EndHeight < clock.StartHeight {
			return nil, ErrState("invalid epoch clock")
		}
		if clock.ValidatorSetId == 0 {
			clock.ValidatorSetId = params.ValidatorSetId
		}
		if clock.EpochBlocks == 0 {
			clock.EpochBlocks = params.EpochBlocks
		}
		if clock.ValidatorHandoffNoticeSeconds == 0 {
			clock.ValidatorHandoffNoticeSeconds = params.ValidatorHandoffNoticeSeconds
		}
		if clock.ValidatorHandoffPrepared {
			if err := validatePreparedValidatorHandoff(clock, c.Config.ChainId); err != nil {
				return nil, err
			}
			frozenRosterHash, err := c.epochValidatorRosterHash(clock.CurrentEpoch + 1)
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(frozenRosterHash, clock.ValidatorHandoffRosterHash) {
				return nil, ErrState("validator handoff roster commitment does not match the frozen snapshot")
			}
		}
		return clock, nil
	}
	var lastEpoch, lastHeight uint64
	marker := new(ReplayMarker)
	if found, readErr := c.read(KeyForLatestEpoch(), marker); readErr != nil {
		return nil, readErr
	} else if found {
		if len(marker.Id) != 8 {
			return nil, ErrState("latest epoch index is invalid")
		}
		lastEpoch = binary.BigEndian.Uint64(marker.Id)
		authorization := new(EpochAuthorization)
		if authorizationFound, authorizationErr := c.read(KeyForEpochAuthorization(lastEpoch), authorization); authorizationErr != nil {
			return nil, authorizationErr
		} else if !authorizationFound || authorization.Epoch != lastEpoch || authorization.EndHeight == 0 {
			return nil, ErrState("latest epoch index references invalid state")
		}
		lastHeight = authorization.EndHeight
	}
	if lastEpoch == math.MaxUint64 || lastHeight == math.MaxUint64 || lastHeight > math.MaxUint64-params.EpochBlocks {
		return nil, ErrState("epoch clock overflow")
	}
	start := lastHeight + 1
	if start == 0 {
		start = 1
	}
	return &EpochClock{
		CurrentEpoch: lastEpoch + 1, StartHeight: start, EndHeight: start + params.EpochBlocks - 1,
		ValidatorSetId: params.ValidatorSetId, EpochBlocks: params.EpochBlocks,
		ValidatorHandoffNoticeSeconds: params.ValidatorHandoffNoticeSeconds,
	}, nil
}

func (c *Contract) currentValidatorSetID(params *ProtocolParams) (uint64, *PluginError) {
	clock, err := c.currentEpochClock(params)
	if err != nil {
		return 0, err
	}
	if clock.ValidatorSetId == 0 {
		return 0, ErrState("validator set identifier is unavailable")
	}
	return clock.ValidatorSetId, nil
}

func (c *Contract) finalizeEpoch(clock *EpochClock, currentAddress []byte, current *ProducerRecord, params *ProtocolParams, records map[string]proto.Message) *PluginError {
	epoch, height := clock.CurrentEpoch, clock.EndHeight
	if found, err := c.read(KeyForEpochAuthorization(epoch), new(EpochAuthorization)); err != nil {
		return err
	} else if found {
		return ErrConflict("epoch authorization already exists")
	}
	entries, err := c.rangeRead(ProducerPrefix(epoch))
	if err != nil {
		return err
	}
	producers := make(map[string]*ProducerRecord, len(entries)+1)
	for _, entry := range entries {
		record := new(ProducerRecord)
		if decodeErr := Unmarshal(entry.Value, record); decodeErr != nil {
			return decodeErr
		}
		producers[string(record.ProducerAddress)] = record
	}
	producers[string(currentAddress)] = current
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
	authorization := &EpochAuthorization{
		Epoch: epoch, StartHeight: clock.StartHeight, EndHeight: height,
		ValidatorSetId: clock.ValidatorSetId, Status: "authorized",
	}
	records[string(KeyForLatestEpoch())] = &ReplayMarker{Id: uint64Bytes(epoch)}
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
		servicer := new(Servicer)
		if found, readErr := c.readStaged(records, KeyForServicer(record.ProducerAddress), servicer); readErr != nil {
			return readErr
		} else if found {
			if ^uint64(0)-servicer.AccruedRewards < amount {
				return ErrState("servicer reward accounting overflow")
			}
			servicer.AccruedRewards += amount
			// Every reward is minted on Base. It may increase a Canopy bond only
			// after the resulting tokens are explicitly bridged and staked.
			servicer.AutoCompound = false
			if amount != 0 {
				recipients, amounts = append(recipients, payout), append(amounts, amount)
			}
			records[string(KeyForServicer(record.ProducerAddress))] = servicer
		} else if amount != 0 {
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
	authorization.CompoundedAmount = 0
	authorization.ProducerAmount = producerTotal
	authorization.TotalAmount = authorization.ProducerAmount + treasury
	if authorization.TotalAmount != 0 {
		authorization.CanonicalChainDigest = epochAuthorizationDigest(params, clock.ValidatorSetId, epoch, recipients, amounts)
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
