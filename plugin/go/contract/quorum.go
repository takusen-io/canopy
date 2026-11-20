package contract

import (
	"bytes"
	"encoding/hex"
	"math/big"

	"github.com/drand/kyber"
	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bdn"
	kilicbls "github.com/kilic/bls12-381"
	"google.golang.org/protobuf/proto"
)

const bdnSignatureSize = 96

func quorumProofID(kind string, setID uint64, digest []byte) []byte {
	return hashFields([]byte("takusen:evm-quorum-proof"), []byte(kind), uint64Bytes(setID), digest)
}

func (c *Contract) deliverGovernanceVote(height uint64, vote *MessageGovernanceVote) *PluginDeliverResponse {
	if len(vote.Digest) != 32 || !bytes.Equal(vote.ProposalId, quorumProofID("governance-action", vote.ValidatorSetId, vote.Digest)) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("governance proposal identity does not match its signed digest")}
	}
	if found, err := c.read(KeyForQuorumProof(vote.ProposalId), new(QuorumProof)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("governance proposal already finalized")}
	}

	snapshot, err := c.activeValidatorSnapshot()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	if vote.ValidatorSetId != snapshot.validatorSetID {
		return &PluginDeliverResponse{Error: ErrUnauthorized("governance vote does not use the active validator snapshot")}
	}
	validator, ok := snapshot.validators[hex.EncodeToString(vote.ValidatorAddress)]
	if !ok {
		return &PluginDeliverResponse{Error: ErrUnauthorized("governance voter is not an active validator")}
	}
	publicKey, cryptoErr := bdnPublicKey(validator.PublicKey)
	if cryptoErr != nil || bdnScheme().Verify(publicKey, vote.Digest, vote.Signature) != nil {
		return &PluginDeliverResponse{Error: ErrCrypto("invalid governance BDN signature share")}
	}

	shareKey := KeyForQuorumShare(vote.ProposalId, vote.ValidatorAddress)
	if found, readErr := c.read(shareKey, new(QuorumSignatureShare)); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("validator already voted on this governance proposal")}
	}
	share := &QuorumSignatureShare{ProofId: vote.ProposalId, ObserverAddress: vote.ValidatorAddress, Signature: vote.Signature, ObservedHeight: height}
	records := map[string]proto.Message{string(shareKey): share}

	validators := make([]*Validator, 0, len(snapshot.validators))
	for _, member := range snapshot.validators {
		validators = append(validators, member)
	}
	sortValidatorsByConsensusOrder(validators)
	shares, readErr := c.rangeRead(QuorumShareProofPrefix(vote.ProposalId))
	if readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	}
	signatures := map[string][]byte{hex.EncodeToString(vote.ValidatorAddress): vote.Signature}
	for _, entry := range shares {
		stored := new(QuorumSignatureShare)
		if decodeErr := Unmarshal(entry.Value, stored); decodeErr != nil {
			return &PluginDeliverResponse{Error: decodeErr}
		}
		signatures[hex.EncodeToString(stored.ObserverAddress)] = stored.Signature
	}

	var signedWeight uint64
	for _, member := range validators {
		if _, signed := signatures[hex.EncodeToString(member.Address)]; signed {
			if ^uint64(0)-signedWeight < member.StakedAmount {
				return &PluginDeliverResponse{Error: ErrState("signed validator stake overflow")}
			}
			signedWeight += member.StakedAmount
		}
	}
	left := new(big.Int).Mul(new(big.Int).SetUint64(signedWeight), big.NewInt(3))
	right := new(big.Int).Mul(new(big.Int).SetUint64(snapshot.totalStake), big.NewInt(2))
	if left.Cmp(right) <= 0 {
		if writeErr := c.write(records); writeErr != nil {
			return &PluginDeliverResponse{Error: writeErr}
		}
		return &PluginDeliverResponse{}
	}

	proof, proofErr := buildGovernanceProof(height, vote, validators, signatures, signedWeight, snapshot.totalStake)
	if proofErr != nil {
		return &PluginDeliverResponse{Error: ErrCrypto(proofErr.Error())}
	}
	delete(records, string(shareKey))
	records[string(KeyForQuorumProof(vote.ProposalId))] = proof
	deletes := make([][]byte, 0, len(shares)+1)
	deletes = append(deletes, shareKey)
	for _, entry := range shares {
		deletes = append(deletes, entry.Key)
	}
	if writeErr := c.writeChanges(records, deletes); writeErr != nil {
		return &PluginDeliverResponse{Error: writeErr}
	}
	return &PluginDeliverResponse{}
}

func buildGovernanceProof(height uint64, vote *MessageGovernanceVote, validators []*Validator, signatures map[string][]byte, signedWeight, totalWeight uint64) (*QuorumProof, error) {
	suite := drandbls.NewBLS12381Suite()
	points := make([]kyber.Point, len(validators))
	for i, validator := range validators {
		point, err := bdnPublicKey(validator.PublicKey)
		if err != nil {
			return nil, err
		}
		points[i] = point
	}
	mask, err := sign.NewMask(suite, points, nil)
	if err != nil {
		return nil, err
	}
	partialSignatures := make([][]byte, 0, len(signatures))
	for i, validator := range validators {
		if signature, ok := signatures[hex.EncodeToString(validator.Address)]; ok {
			if err = mask.SetBit(i, true); err != nil {
				return nil, err
			}
			partialSignatures = append(partialSignatures, signature)
		}
	}
	scheme := bdn.NewSchemeOnG2(suite)
	aggregate, err := scheme.AggregateSignatures(partialSignatures, mask)
	if err != nil {
		return nil, err
	}
	aggregatePublicKey, err := scheme.AggregatePublicKeys(mask)
	if err != nil {
		return nil, err
	}
	aggregateSignature, err := aggregate.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if err = scheme.Verify(aggregatePublicKey, vote.Digest, aggregateSignature); err != nil {
		return nil, err
	}
	eipSignature, err := g2CompressedToEIP2537(aggregateSignature)
	if err != nil {
		return nil, err
	}
	return &QuorumProof{
		ProofKind: "governance-action", ProofId: vote.ProposalId, Digest: vote.Digest,
		ValidatorSetId: vote.ValidatorSetId, SignerBitmap: mask.Mask(),
		AggregateSignatureEip2537: eipSignature, SignedWeight: signedWeight,
		TotalWeight: totalWeight, CompletedHeight: height,
	}, nil
}

func bdnScheme() *bdn.Scheme { return bdn.NewSchemeOnG2(drandbls.NewBLS12381Suite()) }

func bdnPublicKey(compressed []byte) (kyber.Point, error) {
	point := drandbls.NewBLS12381Suite().G1().Point()
	if err := point.UnmarshalBinary(compressed); err != nil {
		return nil, err
	}
	return point, nil
}

func (c *Contract) verifyValidatorCertificate(digest []byte, validatorSetID uint64, bitmap, aggregate []byte) *PluginError {
	snapshot, err := c.activeValidatorSnapshot()
	if err != nil {
		return err
	}
	return verifyValidatorCertificateWithSnapshot(digest, validatorSetID, bitmap, aggregate, snapshot)
}

func verifyValidatorCertificateWithSnapshot(digest []byte, validatorSetID uint64, bitmap, aggregate []byte, snapshot *activeValidatorSnapshot) *PluginError {
	if snapshot == nil || validatorSetID == 0 || validatorSetID != snapshot.validatorSetID || len(aggregate) != bdnSignatureSize {
		return ErrUnauthorized("certificate does not use the governed validator set")
	}
	validators := make([]*Validator, 0, len(snapshot.validators))
	for _, validator := range snapshot.validators {
		validators = append(validators, validator)
	}
	sortValidatorsByConsensusOrder(validators)
	suite := drandbls.NewBLS12381Suite()
	points := make([]kyber.Point, len(validators))
	for i, validator := range validators {
		point, pointErr := bdnPublicKey(validator.PublicKey)
		if pointErr != nil {
			return ErrCrypto("certificate contains an invalid validator public key")
		}
		points[i] = point
	}
	mask, maskErr := sign.NewMask(suite, points, nil)
	if maskErr != nil || mask.SetMask(bitmap) != nil {
		return ErrCrypto("certificate signer bitmap is invalid")
	}
	var signedWeight uint64
	for i, validator := range validators {
		if bitmap[i/8]&(1<<uint(i&7)) == 0 {
			continue
		}
		if ^uint64(0)-signedWeight < validator.StakedAmount {
			return ErrState("certificate signer stake overflow")
		}
		signedWeight += validator.StakedAmount
	}
	left := new(big.Int).Mul(new(big.Int).SetUint64(signedWeight), big.NewInt(3))
	right := new(big.Int).Mul(new(big.Int).SetUint64(snapshot.totalStake), big.NewInt(2))
	if left.Cmp(right) <= 0 {
		return ErrUnauthorized("certificate does not contain strict two-thirds stake")
	}
	aggregatePublicKey, aggregateErr := bdn.NewSchemeOnG2(suite).AggregatePublicKeys(mask)
	if aggregateErr != nil || bdn.NewSchemeOnG2(suite).Verify(aggregatePublicKey, digest, aggregate) != nil {
		return ErrCrypto("certificate aggregate signature is invalid")
	}
	return nil
}

func g2CompressedToEIP2537(compressed []byte) ([]byte, error) {
	g2 := kilicbls.NewG2()
	point, err := g2.FromCompressed(compressed)
	if err != nil {
		return nil, err
	}
	// kilic serializes Fp2 as c1 || c0; EIP-2537 requires c0 || c1,
	// and pads each 48-byte field element to 64 bytes.
	raw := g2.ToUncompressed(point)
	result := make([]byte, 256)
	for coordinate := 0; coordinate < 2; coordinate++ {
		source := coordinate * 96
		target := coordinate * 128
		copy(result[target+16:target+64], raw[source+48:source+96])
		copy(result[target+80:target+128], raw[source:source+48])
	}
	return result, nil
}

func g1CompressedToEIP2537(compressed []byte) ([]byte, error) {
	g1 := kilicbls.NewG1()
	point, err := g1.FromCompressed(compressed)
	if err != nil {
		return nil, err
	}
	raw := g1.ToUncompressed(point)
	result := make([]byte, 128)
	copy(result[16:64], raw[:48])
	copy(result[80:128], raw[48:])
	return result, nil
}
