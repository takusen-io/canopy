package bft

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/canopy-network/canopy/lib"
	"github.com/canopy-network/canopy/lib/crypto"
)

const (
	maxVDFElementSize = 1024
	maxVDFIterations  = uint64(1<<31 - 1)
)

// LEADER TRACKING AND AGGREGATING MESSAGES FROM REPLICAS

// NOTE: A 'Vote' is a digital signature of SignBytes from a Replica Validator. By signing a message and sending it to the Leader,
// the Replica is adding their Voting power (staked tokens) behind some aggregable Message. If the Leader is able to aggregate +2/3rds of the Voting Power,
// the Leader is able to justify consensus on some Message to the entire set.

type (
	// VotesForHeight is exclusively used by the Leader to track votes from Replicas for each phase
	VotesForHeight map[uint64]map[string]map[string]*VoteSet // [Round] -> [Phase] -> [Payload-Hash] -> VoteSet
	// VoteSet holds the unique Vote Message, a power count of the Replicas who have voted for this, and an aggregation of the Replicas signatures to prove the vote count
	VoteSet struct {
		Vote            *Message               `json:"vote,omitempty"`
		TotalVotedPower uint64                 `json:"totalVotedPower,omitempty"`
		multiKey        crypto.MultiPublicKeyI // tracks and aggregates bls signatures from replicas
		auxiliary       map[string]*auxiliaryVoteSet
	}
	auxiliaryVoteSet struct {
		candidate *lib.AuxiliaryCandidate
		power     uint64
		multiKey  crypto.MultiPublicKeyI
	}
)

const maxAuxiliaryVotes = 32

func auxiliaryCandidateID(candidate *lib.AuxiliaryCandidate) string {
	payloadHash := sha256.Sum256(candidate.Payload)
	return candidate.Kind + ":" + hex.EncodeToString(candidate.Key) + ":" + hex.EncodeToString(candidate.Digest) + ":" + hex.EncodeToString(payloadHash[:])
}

func validAuxiliaryCandidate(candidate *lib.AuxiliaryCandidate) bool {
	return candidate != nil && len(candidate.Kind) > 0 && len(candidate.Kind) <= 64 && len(candidate.Key) > 0 && len(candidate.Key) <= 128 && len(candidate.Digest) == 32 && len(candidate.Payload) <= 16<<10
}

// GetMajorityVote() returns the Message and AggregateSignature with a VoteSet with a +2/3 majority from the Replicas
// NOTE: Votes for a specific Height-Round-Phase are organized by `Payload Hash` to ensure that all Replicas are voting on the same proposal
func (b *BFT) GetMajorityVote() (m *Message, sig *lib.AggregateSignature, err lib.ErrorI) {
	for _, voteSet := range b.Votes[b.View.Round][phaseToString(b.View.Phase-1)] {
		if has23maj := voteSet.TotalVotedPower >= b.ValidatorSet.MinimumMaj23; has23maj {
			signature, e := voteSet.multiKey.AggregateSignatures()
			if e != nil {
				return nil, nil, ErrAggregateSignature(e)
			}
			return voteSet.Vote, &lib.AggregateSignature{Signature: signature, Bitmap: voteSet.multiKey.Bitmap()}, nil
		}
	}
	return nil, nil, lib.ErrNoMaj23()
}

// AllVotingPowerReceived reports whether every validator has signed the payload that reached
// quorum in the preceding phase. It is used only to maximize healthy signer participation; a
// quorum remains sufficient for safety and liveness once the bounded collection window expires.
func (b *BFT) AllVotingPowerReceived() bool {
	for _, voteSet := range b.Votes[b.View.Round][phaseToString(b.View.Phase-1)] {
		if voteSet.TotalVotedPower >= b.ValidatorSet.TotalPower {
			return true
		}
	}
	return false
}

// GetLeadingVote() returns the unique Vote Message that has the most power behind it and the number and percent voted that voted for it
func (b *BFT) GetLeadingVote() (m *Message, maxVotePercent uint64, maxVotes uint64) {
	for _, voteSet := range b.Votes[b.View.Round][phaseToString(b.View.Phase-1)] {
		if voteSet.TotalVotedPower >= maxVotes {
			m, maxVotes, maxVotePercent = voteSet.Vote, voteSet.TotalVotedPower, lib.Uint64PercentageDiv(voteSet.TotalVotedPower, b.ValidatorSet.TotalPower)
		}
	}
	return
}

// AddVote() adds a Replica's vote to the VoteSet
func (b *BFT) AddVote(vote *Message) lib.ErrorI {
	b.Controller.Lock()
	defer b.Controller.Unlock()
	voteSet := b.getVoteSet(vote)
	// add the vote to the set
	if err := b.addSigToVoteSet(vote, voteSet); err != nil {
		return err
	}
	// optional attachments don't invalidate the signed vote
	if err := b.handleHighQCVDFAndEvidence(vote); err != nil {
		b.log.Warnf("Ignoring invalid vote attachment: %s", err.Error())
	}
	return nil
}

// getVoteSet() returns the set of votes for the Round.Phase.Payload
func (b *BFT) getVoteSet(vote *Message) (voteSet *VoteSet) {
	// initialize helper variables
	round, phase, ok := vote.Qc.Header.Round, phaseToString(vote.Qc.Header.Phase), false
	// ensure Votes for this Round are initialized
	if _, ok = b.Votes[round]; !ok {
		b.Votes[round] = make(map[string]map[string]*VoteSet)
	}
	// ensure Votes for this Round.Phase are initialized
	if _, ok = b.Votes[round][phase]; !ok {
		b.Votes[round][phase] = make(map[string]*VoteSet)
	}
	// the string version of the SignBytes act as a unique key for Replicas to vote on
	// the SignBytes also are the bytes the Replicas use to sign and Validate an Aggregate Signature
	payload := crypto.HashString(vote.SignBytes())
	// if no VoteSet is created for this Round.Phase.Payload then create a new VoteSet
	if voteSet, ok = b.Votes[round][phase][payload]; !ok {
		voteSet = &VoteSet{
			Vote:      vote,
			multiKey:  b.ValidatorSet.MultiKey.Copy(),
			auxiliary: make(map[string]*auxiliaryVoteSet),
		}
		b.Votes[round][phase][payload] = voteSet
	}
	return
}

// addSigToVoteSet() adds the digital signature from the Replica to the VoteSet
func (b *BFT) addSigToVoteSet(vote *Message, voteSet *VoteSet) (err lib.ErrorI) {
	b.log.Debugf("Adding vote from replica: %s", lib.BytesToTruncatedString(vote.Signature.PublicKey))
	val, idx, err := b.ValidatorSet.GetValidatorAndIdx(vote.Signature.PublicKey)
	if err != nil {
		return err
	}
	enabled, er := voteSet.multiKey.SignerEnabledAt(idx)
	if er != nil {
		return lib.ErrInvalidValidatorIndex()
	}
	if enabled {
		return ErrDuplicateVote()
	}
	voteSet.TotalVotedPower += val.VotingPower
	if er = voteSet.multiKey.AddSigner(vote.Signature.Signature, idx); er != nil {
		return ErrUnableToAddSigner(er)
	}
	// Auxiliary signatures are best-effort attachments. Missing, malformed, or
	// conflicting attachments never invalidate the ordinary consensus vote.
	if vote.Qc.Header.Phase != PrecommitVote || len(vote.AuxiliaryVotes) > maxAuxiliaryVotes {
		return nil
	}
	publicKey, keyErr := crypto.BytesToBLS12381Public(vote.Signature.PublicKey)
	if keyErr != nil {
		return nil
	}
	logicalKeys := make(map[string]struct{}, len(vote.AuxiliaryVotes))
	for _, attachment := range vote.AuxiliaryVotes {
		if attachment == nil || !validAuxiliaryCandidate(attachment.Candidate) || len(attachment.Signature) != crypto.BLS12381SignatureSize ||
			!publicKey.VerifyBytes(lib.AuxiliaryCandidateSignBytes(attachment.Candidate), attachment.Signature) {
			continue
		}
		logical := attachment.Candidate.Kind + ":" + hex.EncodeToString(attachment.Candidate.Key)
		if _, duplicate := logicalKeys[logical]; duplicate {
			continue
		}
		logicalKeys[logical] = struct{}{}
		id := auxiliaryCandidateID(attachment.Candidate)
		set := voteSet.auxiliary[id]
		if set == nil {
			set = &auxiliaryVoteSet{candidate: attachment.Candidate, multiKey: b.ValidatorSet.MultiKey.Copy()}
			voteSet.auxiliary[id] = set
		}
		if enabled, enableErr := set.multiKey.SignerEnabledAt(idx); enableErr != nil || enabled {
			continue
		}
		if addErr := set.multiKey.AddSigner(attachment.Signature, idx); addErr == nil {
			set.power += val.VotingPower
		}
	}
	return
}

// AuxiliaryCertificates returns bounded strict >2/3 BDN certificates.
func (b *BFT) AuxiliaryCertificates(vote *Message) []*lib.AuxiliaryCertificate {
	if vote == nil || vote.Qc == nil || vote.Qc.Header == nil {
		return nil
	}
	payload := crypto.HashString(vote.SignBytes())
	voteSet := b.Votes[vote.Qc.Header.Round][phaseToString(vote.Qc.Header.Phase)][payload]
	if voteSet == nil {
		return nil
	}
	result := make([]*lib.AuxiliaryCertificate, 0, len(voteSet.auxiliary))
	for _, set := range voteSet.auxiliary {
		if set.power*3 <= b.ValidatorSet.TotalPower*2 {
			continue
		}
		signature, err := set.multiKey.AggregateSignatures()
		if err == nil {
			result = append(result, &lib.AuxiliaryCertificate{Candidate: set.candidate, Signature: &lib.AggregateSignature{Signature: signature, Bitmap: set.multiKey.Bitmap()}})
		}
	}
	return result
}

// handleHighQCVDFAndEvidence() processes any 'highQC', 'vdf' or 'evidence' an ElectionVote from a Replica may have submitted
func (b *BFT) handleHighQCVDFAndEvidence(vote *Message) lib.ErrorI {
	// Replicas sending in highQC & evidences to proposer during election vote
	if vote.Qc.Header.Phase == ElectionVote {
		if vote.HighQc != nil {
			// check the highQC for a valid header
			if err := vote.HighQc.Header.Check(&lib.View{
				Phase:     PrecommitVote,
				NetworkId: b.NetworkId,
				ChainId:   b.ChainId,
			}, false); err != nil {
				return err
			}
			// ensure the highQC has a valid Quorum Certificate using the n-1 height because state machine heights are 'end state' once committed
			vs, err := b.Controller.LoadCommittee(b.LoadRootChainId(vote.HighQc.Header.Height), vote.HighQc.Header.RootHeight)
			if err != nil {
				return err
			}
			// ensure the height of the HighQC isn't older than the stateCommitteeHeight of the committee
			// as anything older is invalid and at risk of a 'long range attack'
			if err = vote.HighQc.CheckHighQC(lib.GlobalMaxBlockSize, b.View, b.CommitteeData.LastRootHeightUpdated, vs); err != nil {
				return err
			}
			// save the highQC if it's higher than any the Leader currently is aware of
			if b.HighQC == nil || b.HighQC.Header.Less(vote.HighQc.Header) {
				b.log.Infof("Replica %s submitted a highQC", lib.BytesToTruncatedString(vote.Signature.PublicKey))
				b.HighQC = vote.HighQc
				b.Block, b.Results = vote.Qc.Block, vote.Qc.Results
				b.RCBuildHeight = vote.RcBuildHeight
			}
		}
		// pre handle VDF if enabled
		if b.Config.RunVDF && vote.Vdf != nil && vote.Vdf.Iterations != 0 {
			if len(vote.Vdf.Proof) > maxVDFElementSize || len(vote.Vdf.Output) > maxVDFElementSize || vote.Vdf.Iterations > maxVDFIterations {
				return lib.ErrInvalidVDF()
			}
			// save the obtained VDF vote to be processed at the PROPOSE phase
			b.VDFCache = append(b.VDFCache, vote)
		}
		// combine double sign evidence
		for _, evidence := range vote.LastDoubleSignEvidence {
			b.log.Infof("Replica %s submitted double sign evidence", lib.BytesToTruncatedString(vote.Signature.PublicKey))
			if err := b.AddDSE(&b.ByzantineEvidence.DSE, evidence); err != nil {
				b.log.Warnf("Replica %s evidence invalid: %s", lib.BytesToTruncatedString(vote.Signature.PublicKey), err.Error())
			}
		}
	}
	return nil
}
