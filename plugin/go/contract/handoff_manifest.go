package contract

import (
	"bytes"
	"encoding/binary"
	"sort"

	"github.com/drand/kyber"
	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"golang.org/x/crypto/sha3"
)

const handoffDomainLeafType = "ValidatorHandoffDomain(uint64 nativeChainId,uint64 epoch,uint64 oldSetId,uint64 newSetId,bytes32 frozenRosterHash,bytes32 frozenDomainSetHash,uint64 attempt,bytes32 handoffGeneration,uint64 handoffTimestamp,uint64 outgoingAuthorityCutoff,bytes32 settlementDomain,uint64 evmChainId,address verifier,uint64 rotationNonce,bytes32 validatorKeysHash,bytes32 validatorWeightsHash)"
const handoffCancellationLeafType = "CancelValidatorHandoffDomain(uint64 nativeChainId,uint64 epoch,uint64 oldSetId,uint64 newSetId,bytes32 handoffGeneration,uint64 handoffTimestamp,bytes32 settlementDomain,uint64 evmChainId,address verifier,uint64 rotationNonce,bytes32 pendingValidatorSetHash)"

func keccakParts(parts ...[]byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	return hash.Sum(nil)
}

func abiWordUint64(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}

func abiWordBytes(value []byte) []byte {
	word := make([]byte, 32)
	copy(word[32-len(value):], value)
	return word
}

func abiEncodeBytesArray(values [][]byte) []byte {
	result := append([]byte(nil), abiWordUint64(32)...)
	tail := append([]byte(nil), abiWordUint64(uint64(len(values)))...)
	offset := 32 * len(values)
	data := make([]byte, 0)
	for _, value := range values {
		tail = append(tail, abiWordUint64(uint64(offset))...)
		encoded := append([]byte(nil), abiWordUint64(uint64(len(value)))...)
		encoded = append(encoded, value...)
		if remainder := len(encoded) % 32; remainder != 0 {
			encoded = append(encoded, make([]byte, 32-remainder)...)
		}
		data = append(data, encoded...)
		offset += len(encoded)
	}
	return append(append(result, tail...), data...)
}

func abiEncodeUint96Array(values []uint64) []byte {
	result := append([]byte(nil), abiWordUint64(32)...)
	result = append(result, abiWordUint64(uint64(len(values)))...)
	for _, value := range values {
		result = append(result, abiWordUint64(value)...)
	}
	return result
}

func abiEncodeValidatorSet(keys [][]byte, weights []uint64) []byte {
	encodedKeys := abiEncodeBytesArray(keys)[32:]
	encodedWeights := abiEncodeUint96Array(weights)[32:]
	result := append([]byte(nil), abiWordUint64(64)...)
	result = append(result, abiWordUint64(uint64(64+len(encodedKeys)))...)
	result = append(result, encodedKeys...)
	return append(result, encodedWeights...)
}

func (c *Contract) evmRosterHashes(epoch uint64, encoded []byte) ([]byte, []byte, []byte, *PluginError) {
	validators := make([]*Validator, 0)
	if len(encoded) != 0 {
		decoded, err := decodeActiveValidatorSet(encoded, c.Config.ChainId)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, value := range decoded {
			validators = append(validators, value.(*Validator))
		}
	} else {
		entries, err := c.rangeRead(EpochValidatorPrefix(epoch))
		if err != nil {
			return nil, nil, nil, err
		}
		for _, entry := range entries {
			validator := new(Validator)
			if decodeErr := Unmarshal(entry.Value, validator); decodeErr != nil {
				return nil, nil, nil, decodeErr
			}
			validators = append(validators, validator)
		}
	}
	if len(validators) < 2 {
		return nil, nil, nil, ErrState("prepared validator set is too small")
	}
	sortValidatorsByConsensusOrder(validators)
	points := make([]kyber.Point, len(validators))
	for index, validator := range validators {
		point, pointErr := bdnPublicKey(validator.PublicKey)
		if pointErr != nil {
			return nil, nil, nil, ErrCrypto("prepared validator public key is invalid")
		}
		points[index] = point
	}
	mask, maskErr := sign.NewMask(drandbls.NewBLS12381Suite(), points, nil)
	if maskErr != nil {
		return nil, nil, nil, ErrCrypto("prepared validator mask is invalid")
	}
	keys := make([][]byte, len(validators))
	weights := make([]uint64, len(validators))
	for index, validator := range validators {
		if mask.SetBit(index, true) != nil {
			return nil, nil, nil, ErrCrypto("prepared validator mask is invalid")
		}
		weighted, aggregateErr := bdnScheme().AggregatePublicKeys(mask)
		if aggregateErr != nil {
			return nil, nil, nil, ErrCrypto("prepared validator key aggregation failed")
		}
		compressed, marshalErr := weighted.MarshalBinary()
		if marshalErr != nil {
			return nil, nil, nil, ErrCrypto("prepared validator key encoding failed")
		}
		if mask.SetMask(make([]byte, len(mask.Mask()))) != nil {
			return nil, nil, nil, ErrCrypto("prepared validator mask reset failed")
		}
		keys[index], marshalErr = g1CompressedToEIP2537(compressed)
		if marshalErr != nil {
			return nil, nil, nil, ErrCrypto("prepared validator key conversion failed")
		}
		weights[index] = validator.StakedAmount
	}
	return keccak256(abiEncodeBytesArray(keys)), keccak256(abiEncodeUint96Array(weights)), keccak256(abiEncodeValidatorSet(keys, weights)), nil
}

func handoffLeafHash(manifest *ValidatorHandoffManifest, domain *ValidatorHandoffDomainManifest) []byte {
	return keccakParts(
		keccak256([]byte(handoffDomainLeafType)),
		abiWordUint64(manifest.NativeChainId), abiWordUint64(manifest.Epoch),
		abiWordUint64(manifest.OldValidatorSetId), abiWordUint64(manifest.NewValidatorSetId),
		manifest.FrozenRosterHash, manifest.FrozenDomainSetHash, abiWordUint64(manifest.Attempt),
		manifest.Generation, abiWordUint64(manifest.HandoffTimestamp),
		abiWordUint64(manifest.OutgoingAuthorityCutoff), domain.SettlementDomainId,
		abiWordUint64(domain.EvmChainId), abiWordBytes(domain.VerifierAddress),
		abiWordUint64(domain.RotationNonce), domain.ValidatorKeysHash, domain.ValidatorWeightsHash,
	)
}

func handoffCancellationLeafHash(manifest *ValidatorHandoffCancellationManifest, domain *ValidatorHandoffCancellationDomainManifest) []byte {
	return keccakParts(
		keccak256([]byte(handoffCancellationLeafType)), abiWordUint64(manifest.NativeChainId),
		abiWordUint64(manifest.Epoch), abiWordUint64(manifest.OldValidatorSetId),
		abiWordUint64(manifest.NewValidatorSetId), manifest.HandoffGeneration,
		abiWordUint64(manifest.HandoffTimestamp), domain.SettlementDomainId,
		abiWordUint64(domain.EvmChainId), abiWordBytes(domain.VerifierAddress),
		abiWordUint64(domain.RotationNonce), domain.PendingValidatorSetHash,
	)
}

func handoffMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	level := make([][]byte, len(leaves))
	for index := range leaves {
		level[index] = append([]byte(nil), leaves[index]...)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			right := level[index]
			if index+1 < len(level) {
				right = level[index+1]
			}
			next = append(next, keccakParts(level[index], right))
		}
		level = next
	}
	return level[0]
}

func handoffMerkleProof(leaves [][]byte, position int) [][]byte {
	proof := make([][]byte, 0)
	level := leaves
	index := position
	for len(level) > 1 {
		sibling := index ^ 1
		if sibling >= len(level) {
			sibling = index
		}
		proof = append(proof, append([]byte(nil), level[sibling]...))
		next := make([][]byte, 0, (len(level)+1)/2)
		for cursor := 0; cursor < len(level); cursor += 2 {
			right := level[cursor]
			if cursor+1 < len(level) {
				right = level[cursor+1]
			}
			next = append(next, keccakParts(level[cursor], right))
		}
		level = next
		index /= 2
	}
	return proof
}

func (c *Contract) buildValidatorHandoffManifest(clock *EpochClock, params *ProtocolParams, height uint64, encodedRoster []byte) (*ValidatorHandoffManifest, *PluginError) {
	keysHash, weightsHash, pendingHash, err := c.evmRosterHashes(clock.CurrentEpoch+1, encodedRoster)
	if err != nil {
		return nil, err
	}
	manifest := &ValidatorHandoffManifest{
		CreatedHeight: height, NativeChainId: clock.ValidatorHandoffNativeChainId, Epoch: clock.CurrentEpoch,
		OldValidatorSetId: clock.ValidatorSetId, NewValidatorSetId: clock.ValidatorSetId + 1,
		FrozenRosterHash:    append([]byte(nil), clock.ValidatorHandoffRosterHash...),
		FrozenDomainSetHash: append([]byte(nil), clock.ValidatorHandoffDomainSetHash...),
		Attempt:             clock.ValidatorHandoffAttempt, Generation: validatorHandoffGeneration(clock),
		HandoffTimestamp:        clock.ValidatorHandoffTimestamp,
		OutgoingAuthorityCutoff: clock.ValidatorHandoffOutgoingAuthorityCutoff,
	}
	prior := new(ValidatorHandoffManifest)
	priorFound, priorErr := c.read(KeyForValidatorHandoffManifest(), prior)
	if priorErr != nil {
		return nil, priorErr
	}
	priorDomains := make(map[string]*ValidatorHandoffDomainManifest)
	if priorFound {
		for _, domain := range prior.Domains {
			priorDomains[string(domain.SettlementDomainId)] = domain
		}
	}
	for _, domainID := range clock.ValidatorHandoffDomains {
		var chainID uint64
		var verifier []byte
		if frozen := priorDomains[string(domainID)]; frozen != nil {
			chainID, verifier = frozen.EvmChainId, append([]byte(nil), frozen.VerifierAddress...)
		} else {
			domain, domainErr := settlementDomain(params, domainID, false)
			if domainErr != nil {
				return nil, domainErr
			}
			chainID, verifier = domain.ChainId, append([]byte(nil), domain.VerifierAddress...)
		}
		state := new(SettlementDomainRotationState)
		found, stateErr := c.read(KeyForDomainRotationState(domainID), state)
		if stateErr != nil {
			return nil, stateErr
		}
		nonce := uint64(1)
		if found {
			if state.RotationNonce == ^uint64(0) {
				return nil, ErrState("settlement-domain rotation nonce overflow")
			}
			nonce = state.RotationNonce + 1
		}
		manifest.Domains = append(manifest.Domains, &ValidatorHandoffDomainManifest{
			SettlementDomainId: append([]byte(nil), domainID...), EvmChainId: chainID,
			VerifierAddress: verifier, RotationNonce: nonce,
			ValidatorKeysHash: append([]byte(nil), keysHash...), ValidatorWeightsHash: append([]byte(nil), weightsHash...),
			PendingValidatorSetHash: append([]byte(nil), pendingHash...),
		})
	}
	sort.Slice(manifest.Domains, func(i, j int) bool {
		return bytes.Compare(manifest.Domains[i].SettlementDomainId, manifest.Domains[j].SettlementDomainId) < 0
	})
	leaves := make([][]byte, len(manifest.Domains))
	for index, domain := range manifest.Domains {
		domain.LeafHash = handoffLeafHash(manifest, domain)
		leaves[index] = domain.LeafHash
	}
	manifest.Root = handoffMerkleRoot(leaves)
	return manifest, nil
}

func buildValidatorHandoffCancellationManifest(handoff *ValidatorHandoffManifest, height uint64) (*ValidatorHandoffCancellationManifest, *PluginError) {
	if handoff == nil || len(handoff.Root) != 32 || len(handoff.Domains) == 0 {
		return nil, ErrState("validator handoff cancellation is missing its canonical attempt")
	}
	manifest := &ValidatorHandoffCancellationManifest{
		CreatedHeight: height, NativeChainId: handoff.NativeChainId, Epoch: handoff.Epoch,
		OldValidatorSetId: handoff.OldValidatorSetId, NewValidatorSetId: handoff.NewValidatorSetId,
		HandoffGeneration: append([]byte(nil), handoff.Generation...), HandoffTimestamp: handoff.HandoffTimestamp,
	}
	for _, domain := range handoff.Domains {
		manifest.Domains = append(manifest.Domains, &ValidatorHandoffCancellationDomainManifest{
			SettlementDomainId: append([]byte(nil), domain.SettlementDomainId...), EvmChainId: domain.EvmChainId,
			VerifierAddress: append([]byte(nil), domain.VerifierAddress...), RotationNonce: domain.RotationNonce,
			PendingValidatorSetHash: append([]byte(nil), domain.PendingValidatorSetHash...),
		})
	}
	leaves := make([][]byte, len(manifest.Domains))
	for index, domain := range manifest.Domains {
		domain.LeafHash = handoffCancellationLeafHash(manifest, domain)
		leaves[index] = domain.LeafHash
	}
	manifest.Root = handoffMerkleRoot(leaves)
	return manifest, nil
}
