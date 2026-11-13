package contract

import (
	"bytes"

	"google.golang.org/protobuf/proto"
)

const maxAuxiliaryCertificatesPerBlock = 32

// consumeAuxiliaryCertificates persists relay artifacts that Core has already
// authenticated against the predecessor QC's historical committee. The plugin
// deliberately does not repeat aggregate-signature or quorum verification; it
// derives only signer metadata needed by the public RPC and EVM relayer.
func (c *Contract) consumeAuxiliaryCertificates(height uint64, certificates []*AuxiliaryCertificate) map[string]proto.Message {
	records := make(map[string]proto.Message)
	if len(certificates) == 0 || len(certificates) > maxAuxiliaryCertificatesPerBlock {
		return records
	}
	snapshot, err := c.auxiliaryValidatorSnapshot(height)
	if err != nil {
		return records
	}
	validators := make([]*Validator, 0, len(snapshot.validators))
	for _, validator := range snapshot.validators {
		validators = append(validators, validator)
	}
	sortValidatorsByConsensusOrder(validators)
	for _, certificate := range certificates {
		candidate, signature := certificate.GetCandidate(), certificate.GetSignature()
		if candidate == nil || signature == nil || len(candidate.Kind) == 0 || len(candidate.Kind) > 64 ||
			len(candidate.Key) == 0 || len(candidate.Key) > 128 || len(candidate.Digest) != 32 || len(candidate.Payload) > 16<<10 ||
			len(signature.Signature) != bdnSignatureSize || len(signature.Bitmap) != (len(validators)+7)/8 {
			continue
		}
		var signed uint64
		metadataValid := true
		for index, validator := range validators {
			if signature.Bitmap[index/8]&(1<<uint(index%8)) == 0 {
				continue
			}
			if ^uint64(0)-signed < validator.StakedAmount {
				metadataValid = false
				break
			}
			signed += validator.StakedAmount
		}
		if !metadataValid {
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

// auxiliaryValidatorSnapshot identifies the predecessor signer epoch using the
// plugin's already-persisted epoch snapshots. No historical roster crosses the
// Core/plugin boundary.
func (c *Contract) auxiliaryValidatorSnapshot(height uint64) (*activeValidatorSnapshot, *PluginError) {
	clock, clockErr := c.currentEpochClockFromState()
	if clockErr != nil {
		return nil, clockErr
	}
	epoch, validatorSetID := clock.CurrentEpoch, clock.ValidatorSetId
	// The predecessor QC at the first block of an epoch always belongs to the
	// previous epoch, even when the weighted roster (and therefore set ID) did
	// not change across the boundary.
	if height == clock.StartHeight && clock.CurrentEpoch > 1 {
		epoch--
		previousHash, previousErr := c.epochValidatorRosterHash(clock.CurrentEpoch - 1)
		if previousErr != nil {
			return nil, previousErr
		}
		activeHash, hashErr := c.epochValidatorRosterHash(clock.CurrentEpoch)
		if hashErr != nil {
			return nil, hashErr
		}
		if !bytes.Equal(previousHash, activeHash) {
			if validatorSetID <= 1 {
				return nil, ErrState("auxiliary validator set identifier underflow")
			}
			validatorSetID--
		}
	}
	return c.validatorSnapshot(epoch, validatorSetID)
}
