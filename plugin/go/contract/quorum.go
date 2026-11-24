package contract

import (
	"math/big"

	"github.com/drand/kyber"
	drandbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/bdn"
	kilicbls "github.com/kilic/bls12-381"
)

const bdnSignatureSize = 96

func quorumProofID(kind string, setID uint64, digest []byte) []byte {
	return hashFields([]byte("takusen:evm-quorum-proof"), []byte(kind), uint64Bytes(setID), digest)
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
