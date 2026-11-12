package contract

import (
	"bytes"
	"math/big"
	"sort"

	"google.golang.org/protobuf/proto"
)

const maxAuxiliaryCertificatesPerBlock = 32

// consumeAuxiliaryCertificates persists only certificates whose signer bitmap
// still proves strict >2/3 against the immutable active epoch snapshot. Core
// already verifies every aggregate signature before committing the QC; this
// second, deterministic weight check protects the application boundary and
// gives public RPC durable restart/replay state. Malformed auxiliary material
// is ignored so it can never halt ordinary Native consensus.
func (c *Contract) consumeAuxiliaryCertificates(height uint64, certificates []*AuxiliaryCertificate) map[string]proto.Message {
	records := make(map[string]proto.Message)
	if len(certificates) == 0 || len(certificates) > maxAuxiliaryCertificatesPerBlock {
		return records
	}
	snapshot, err := c.activeValidatorSnapshot()
	if err != nil {
		return records
	}
	validators := make([]*Validator, 0, len(snapshot.validators))
	for _, validator := range snapshot.validators {
		validators = append(validators, validator)
	}
	sort.Slice(validators, func(i, j int) bool { return bytes.Compare(validators[i].PublicKey, validators[j].PublicKey) < 0 })
	for _, certificate := range certificates {
		candidate, signature := certificate.GetCandidate(), certificate.GetSignature()
		if candidate == nil || signature == nil || len(candidate.Kind) == 0 || len(candidate.Kind) > 64 ||
			len(candidate.Key) == 0 || len(candidate.Key) > 128 || len(candidate.Digest) != 32 || len(candidate.Payload) > 16<<10 ||
			len(signature.Signature) != bdnSignatureSize || len(signature.Bitmap) != (len(validators)+7)/8 {
			continue
		}
		var signed uint64
		valid := true
		for index, validator := range validators {
			if signature.Bitmap[index/8]&(1<<uint(index%8)) == 0 {
				continue
			}
			if ^uint64(0)-signed < validator.StakedAmount {
				valid = false
				break
			}
			signed += validator.StakedAmount
		}
		left := new(big.Int).Mul(new(big.Int).SetUint64(signed), big.NewInt(3))
		right := new(big.Int).Mul(new(big.Int).SetUint64(snapshot.totalStake), big.NewInt(2))
		if !valid || left.Cmp(right) <= 0 {
			continue
		}
		eipSignature, conversionErr := g2CompressedToEIP2537(signature.Signature)
		if conversionErr != nil {
			continue
		}
		key := KeyForConsensusCertificate(candidate.Kind, candidate.Key, candidate.Digest)
		if found, readErr := c.read(key, new(ConsensusCertificate)); readErr != nil || found {
			continue
		}
		record := &ConsensusCertificate{
			Kind: candidate.Kind, Key: append([]byte(nil), candidate.Key...), Digest: append([]byte(nil), candidate.Digest...),
			Payload: append([]byte(nil), candidate.Payload...), ValidatorSetId: snapshot.validatorSetID, ValidatorEpoch: snapshot.epoch,
			SignerBitmap: append([]byte(nil), signature.Bitmap...), AggregateSignature: append([]byte(nil), signature.Signature...),
			AggregateSignatureEip2537: eipSignature, SignedWeight: signed, TotalWeight: snapshot.totalStake, CompletedHeight: height,
		}
		if !c.applyNativeAuxiliaryCertificate(height, candidate, record, records) {
			continue
		}
		records[string(key)] = record
	}
	return records
}
