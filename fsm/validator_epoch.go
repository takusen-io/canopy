package fsm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"slices"
	"sort"

	"github.com/canopy-network/canopy/lib"
	"github.com/canopy-network/canopy/lib/crypto"
)

const activeValidatorSetEncodingVersion byte = 1

// EncodeActiveValidatorSet serializes the already-frozen consensus committee
// passed to epoch-aware plugins. The address is included explicitly rather
// than re-derived by plugins, making the core roster the single source of
// truth for identity, public key, voting power, and observer discovery.
func (s *StateMachine) EncodeActiveValidatorSet() ([]byte, lib.ErrorI) {
	committee, err := s.GetCommitteeMembers(s.Config.ChainId)
	if err != nil {
		return nil, err
	}
	return encodeValidatorSet(s.Config.ChainId, committee.ValidatorSet.ValidatorSet)
}

// EncodeValidatorSet serializes an explicitly loaded historical committee for
// plugin verification. Unlike EncodeActiveValidatorSet, it does not consult
// the committee currently active in ephemeral state.
func (s *StateMachine) EncodeValidatorSet(set lib.ValidatorSet) ([]byte, lib.ErrorI) {
	return encodeValidatorSet(s.Config.ChainId, set.ValidatorSet.ValidatorSet)
}

// SetAuxiliaryValidatorSet installs the root-chain-aware committee resolved by
// the controller for the predecessor QC. The FSM cannot safely reconstruct it
// from a nested chain's local historical height.
func (s *StateMachine) SetAuxiliaryValidatorSet(encoded []byte) {
	s.auxiliaryValidatorSet = slices.Clone(encoded)
}

func (s *StateMachine) AuxiliaryValidatorSet() []byte {
	return slices.Clone(s.auxiliaryValidatorSet)
}

// EncodePreparedValidatorSet serializes the committee frozen for the next
// epoch. It is empty until the plugin requests preparation at its handoff
// cutoff, allowing the active committee to authorize the exact next roster.
func (s *StateMachine) EncodePreparedValidatorSet() ([]byte, lib.ErrorI) {
	marker, err := s.Get(KeyForPreparedCommitteeEpoch())
	if err != nil || marker == nil {
		return nil, err
	}
	encoded, err := s.Get(KeyForPreparedCommittee(s.Config.ChainId))
	if err != nil {
		return nil, err
	}
	members := new(lib.ConsensusValidators)
	if encoded != nil {
		if err = lib.Unmarshal(encoded, members); err != nil {
			return nil, err
		}
	}
	return encodeValidatorSet(s.Config.ChainId, members.ValidatorSet)
}

// EncodeCandidateValidatorSet derives the exact committee that would become
// active if the current block closed the epoch. It does not persist anything;
// the epoch-aware plugin consumes it only at the nominal boundary and asks
// core to freeze the same end-block state atomically when rotation is needed.
func (s *StateMachine) EncodeCandidateValidatorSet() ([]byte, lib.ErrorI) {
	validators, err := s.GetValidators()
	if err != nil {
		return nil, err
	}
	set, err := s.deriveValidatorSet(validators, s.Config.ChainId, false)
	if err != nil {
		return nil, err
	}
	return encodeValidatorSet(s.Config.ChainId, set.ValidatorSet.ValidatorSet)
}

func encodeValidatorSet(chainID uint64, members []*lib.ConsensusValidator) ([]byte, lib.ErrorI) {
	var encoded bytes.Buffer
	encoded.WriteByte(activeValidatorSetEncodingVersion)
	_ = binary.Write(&encoded, binary.BigEndian, chainID)
	if len(members) > int(^uint32(0)) {
		return nil, lib.ErrInvalidPluginSchema(fmt.Errorf("active validator set is too large"))
	}
	_ = binary.Write(&encoded, binary.BigEndian, uint32(len(members)))
	for _, member := range members {
		publicKey, keyErr := crypto.NewPublicKeyFromBytes(member.PublicKey)
		if keyErr != nil {
			return nil, lib.ErrInvalidPluginSchema(keyErr)
		}
		address := publicKey.Address().Bytes()
		if len(address) != 20 || len(member.PublicKey) > int(^uint16(0)) || len(member.NetAddress) > int(^uint16(0)) {
			return nil, lib.ErrInvalidPluginSchema(fmt.Errorf("invalid active validator member"))
		}
		encoded.Write(address)
		_ = binary.Write(&encoded, binary.BigEndian, uint16(len(member.PublicKey)))
		encoded.Write(member.PublicKey)
		_ = binary.Write(&encoded, binary.BigEndian, member.VotingPower)
		_ = binary.Write(&encoded, binary.BigEndian, uint16(len(member.NetAddress)))
		encoded.WriteString(member.NetAddress)
	}
	return encoded.Bytes(), nil
}

// PrepareValidatorSets freezes the next epoch's committees. Stake, pause, and
// slash changes after this cutoff remain queued for the following epoch.
func (s *StateMachine) PrepareValidatorSets() lib.ErrorI {
	if marker, err := s.Get(KeyForPreparedCommitteeEpoch()); err != nil || marker != nil {
		return err
	}
	validators, err := s.GetValidators()
	if err != nil {
		return err
	}
	chainIDs := make(map[uint64]struct{})
	for _, validator := range validators {
		if !validator.Delegate {
			for _, chainID := range validator.Committees {
				chainIDs[chainID] = struct{}{}
			}
		}
	}
	it, err := s.Iterator(ActiveCommitteesPrefix())
	if err != nil {
		return err
	}
	for ; it.Valid(); it.Next() {
		segments, decodeErr := decodeLengthPrefixedSafe(it.Key())
		if decodeErr == nil && len(segments) == 3 && len(segments[2]) == 8 {
			chainIDs[binary.BigEndian.Uint64(segments[2])] = struct{}{}
		}
	}
	it.Close()
	ordered := make([]uint64, 0, len(chainIDs))
	for chainID := range chainIDs {
		ordered = append(ordered, chainID)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	for _, chainID := range ordered {
		set, deriveErr := s.deriveValidatorSet(validators, chainID, false)
		if deriveErr != nil {
			return deriveErr
		}
		encoded, marshalErr := lib.Marshal(set.ValidatorSet)
		if marshalErr != nil {
			return marshalErr
		}
		if err = s.Set(KeyForPreparedCommittee(chainID), encoded); err != nil {
			return err
		}
	}
	return s.Set(KeyForPreparedCommitteeEpoch(), formatUint64(s.Height()))
}

// EnsureActiveValidatorSets creates the initial epoch snapshot exactly once.
// Existing networks therefore adopt epoch freezing without rewriting validator
// records or requiring a genesis migration.
func (s *StateMachine) EnsureActiveValidatorSets() lib.ErrorI {
	bz, err := s.Get(KeyForActiveCommitteeEpoch())
	if err != nil || bz != nil {
		return err
	}
	return s.ActivateValidatorSets()
}

// ActivateValidatorSets atomically replaces every frozen consensus committee
// with a snapshot derived from the latest validator accounting state. The
// caller invokes this only after the plugin commits an epoch transition, so all
// pause, slash, stake, unstake, and reward changes become consensus-effective
// together for the following block.
func (s *StateMachine) ActivateValidatorSets() lib.ErrorI {
	if activated, err := s.activatePreparedValidatorSets(); err != nil || activated {
		return err
	}
	validators, err := s.GetValidators() // deliberately bypass the per-block cache
	if err != nil {
		return err
	}
	chainIDs := make(map[uint64]struct{})
	for _, validator := range validators {
		if validator.Delegate {
			continue
		}
		for _, chainID := range validator.Committees {
			chainIDs[chainID] = struct{}{}
		}
	}
	// Preserve an explicit empty snapshot for a committee whose final validator
	// left. A missing key after initialization means "not active", never
	// "fall back to mutable validator records".
	it, err := s.Iterator(ActiveCommitteesPrefix())
	if err != nil {
		return err
	}
	var oldKeys [][]byte
	for ; it.Valid(); it.Next() {
		key := slices.Clone(it.Key())
		oldKeys = append(oldKeys, key)
		segments, decodeErr := decodeLengthPrefixedSafe(key)
		if decodeErr == nil && len(segments) == 3 && len(segments[2]) == 8 {
			chainIDs[binary.BigEndian.Uint64(segments[2])] = struct{}{}
		}
	}
	it.Close()
	if err = s.DeleteAll(oldKeys); err != nil {
		return err
	}
	orderedChainIDs := make([]uint64, 0, len(chainIDs))
	for chainID := range chainIDs {
		orderedChainIDs = append(orderedChainIDs, chainID)
	}
	sort.Slice(orderedChainIDs, func(i, j int) bool { return orderedChainIDs[i] < orderedChainIDs[j] })
	for _, chainID := range orderedChainIDs {
		set, deriveErr := s.deriveValidatorSet(validators, chainID, false)
		if deriveErr != nil {
			return deriveErr
		}
		encoded, marshalErr := lib.Marshal(set.ValidatorSet)
		if marshalErr != nil {
			return marshalErr
		}
		if err = s.Set(KeyForActiveCommittee(chainID), encoded); err != nil {
			return err
		}
	}
	return s.Set(KeyForActiveCommitteeEpoch(), formatUint64(s.Height()))
}

func (s *StateMachine) activatePreparedValidatorSets() (bool, lib.ErrorI) {
	marker, err := s.Get(KeyForPreparedCommitteeEpoch())
	if err != nil || marker == nil {
		return false, err
	}
	prepared, err := s.Iterator(PreparedCommitteesPrefix())
	if err != nil {
		return false, err
	}
	type entry struct {
		chainID uint64
		value   []byte
	}
	var next []entry
	var preparedKeys [][]byte
	for ; prepared.Valid(); prepared.Next() {
		key := slices.Clone(prepared.Key())
		segments, decodeErr := decodeLengthPrefixedSafe(key)
		if decodeErr != nil || len(segments) != 3 || len(segments[2]) != 8 {
			prepared.Close()
			return false, ErrInvalidKey(key)
		}
		next = append(next, entry{chainID: binary.BigEndian.Uint64(segments[2]), value: slices.Clone(prepared.Value())})
		preparedKeys = append(preparedKeys, key)
	}
	prepared.Close()
	active, err := s.Iterator(ActiveCommitteesPrefix())
	if err != nil {
		return false, err
	}
	var activeKeys [][]byte
	for ; active.Valid(); active.Next() {
		activeKeys = append(activeKeys, slices.Clone(active.Key()))
	}
	active.Close()
	if err = s.DeleteAll(activeKeys); err != nil {
		return false, err
	}
	for _, item := range next {
		if err = s.Set(KeyForActiveCommittee(item.chainID), item.value); err != nil {
			return false, err
		}
	}
	if err = s.DeleteAll(preparedKeys); err != nil {
		return false, err
	}
	if err = s.Delete(KeyForPreparedCommitteeEpoch()); err != nil {
		return false, err
	}
	return true, s.Set(KeyForActiveCommitteeEpoch(), formatUint64(s.Height()))
}

func (s *StateMachine) frozenValidatorSet(chainID uint64) (lib.ValidatorSet, bool, lib.ErrorI) {
	epoch, err := s.Get(KeyForActiveCommitteeEpoch())
	if err != nil || epoch == nil {
		return lib.ValidatorSet{}, false, err
	}
	encoded, err := s.Get(KeyForActiveCommittee(chainID))
	if err != nil {
		return lib.ValidatorSet{}, true, err
	}
	members := new(lib.ConsensusValidators)
	if encoded != nil {
		if err = lib.Unmarshal(encoded, members); err != nil {
			return lib.ValidatorSet{}, true, err
		}
	}
	set, err := lib.NewValidatorSet(members)
	return set, true, err
}
