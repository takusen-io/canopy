package contract

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"sort"

	"google.golang.org/protobuf/proto"
)

var (
	accountPrefix   = []byte{1}
	poolPrefix      = []byte{2}
	validatorPrefix = []byte{3}
	enclavePrefix   = []byte{100}
	servicerPrefix  = []byte{101}
	requestPrefix   = []byte{102}
	executionPrefix = []byte{103}
	// Prefix 104 was used by the removed duplicate settlement record.
	observationPrefix                 = []byte{105}
	blockAnchorPrefix                 = []byte{106}
	quorumProofPrefix                 = []byte{107}
	quorumSharePrefix                 = []byte{108}
	depositPrefix                     = []byte{109}
	creditPrefix                      = []byte{110}
	reservationPrefix                 = []byte{111}
	observationClaimPrefix            = []byte{112}
	protocolParamsPrefix              = []byte{113}
	stakeChangePrefix                 = []byte{114}
	unbondingPrefix                   = []byte{115}
	slashEvidencePrefix               = []byte{116}
	producerPayoutPrefix              = []byte{117}
	producerPrefix                    = []byte{118}
	epochAuthorizationPrefix          = []byte{119}
	bridgeStatePrefix                 = []byte{120}
	bridgeMintPrefix                  = []byte{121}
	bridgeNoncePrefix                 = []byte{122}
	bridgeBurnPrefix                  = []byte{123}
	epochClockPrefix                  = []byte{124}
	assignmentIndexPrefix             = []byte{125}
	epochValidatorPrefix              = []byte{126}
	settlementIndexPrefix             = []byte{127}
	producerIdentityPrefix            = []byte{128}
	rotationProofIndexPrefix          = []byte{129}
	pendingSlashPrefix                = []byte{130}
	latestEpochPrefix                 = []byte{131}
	provisionalReservationIndexPrefix = []byte{132}
	activeServicerIndexPrefix         = []byte{133}
	pendingEpochAuthorizationPrefix   = []byte{135}
	pendingBridgeBurnPrefix           = []byte{136}
	handoffManifestPrefix             = []byte{137}
	domainRotationStatePrefix         = []byte{138}
	handoffCancellationManifestPrefix = []byte{139}
	consensusCertificatePrefix        = []byte{140}
	nativeAuthorizationIntentPrefix   = []byte{141}
	pendingAuthorizationPrefix        = []byte{142}
	timeoutCandidateCursorPrefix      = []byte{143}
)

func EnclavePrefix() []byte        { return JoinLenPrefix(enclavePrefix) }
func ServicerPrefix() []byte       { return JoinLenPrefix(servicerPrefix) }
func ActiveServicerPrefix() []byte { return JoinLenPrefix(activeServicerIndexPrefix) }
func RequestPrefix() []byte        { return JoinLenPrefix(requestPrefix) }
func AssignmentIndexPrefix(owner []byte) []byte {
	return JoinLenPrefix(assignmentIndexPrefix, owner)
}
func EpochValidatorPrefix(epoch uint64) []byte {
	return JoinLenPrefix(epochValidatorPrefix, uint64Bytes(epoch))
}
func SettlementIndexPrefix() []byte      { return JoinLenPrefix(settlementIndexPrefix) }
func QuorumProofPrefix() []byte          { return JoinLenPrefix(quorumProofPrefix) }
func ConsensusCertificatePrefix() []byte { return JoinLenPrefix(consensusCertificatePrefix) }
func KeyForNativeAuthorizationIntent(kind string, domainID []byte) []byte {
	return JoinLenPrefix(nativeAuthorizationIntentPrefix, []byte(kind), domainID)
}
func PendingAuthorizationPrefix() []byte { return JoinLenPrefix(pendingAuthorizationPrefix) }
func KeyForTimeoutCandidateCursorCurrent() []byte {
	return JoinLenPrefix(timeoutCandidateCursorPrefix, []byte("current"))
}
func KeyForTimeoutCandidateCursorNext() []byte {
	return JoinLenPrefix(timeoutCandidateCursorPrefix, []byte("next"))
}
func KeyForPendingAuthorization(requestID string) []byte {
	return JoinLenPrefix(pendingAuthorizationPrefix, []byte(requestID))
}
func DepositPrefix() []byte     { return JoinLenPrefix(depositPrefix) }
func CreditPrefix() []byte      { return JoinLenPrefix(creditPrefix) }
func ReservationPrefix() []byte { return JoinLenPrefix(reservationPrefix) }
func ProvisionalReservationPrefix(domainID, requester []byte) []byte {
	return JoinLenPrefix(provisionalReservationIndexPrefix, domainID, requester)
}
func StakeChangePrefix() []byte               { return JoinLenPrefix(stakeChangePrefix) }
func UnbondingPrefix() []byte                 { return JoinLenPrefix(unbondingPrefix) }
func SlashEvidencePrefix() []byte             { return JoinLenPrefix(slashEvidencePrefix) }
func ProducerPayoutPrefix() []byte            { return JoinLenPrefix(producerPayoutPrefix) }
func ProducerPrefix(epoch uint64) []byte      { return JoinLenPrefix(producerPrefix, uint64Bytes(epoch)) }
func ProducerIdentityPrefix() []byte          { return JoinLenPrefix(producerIdentityPrefix) }
func PendingSlashPrefix() []byte              { return JoinLenPrefix(pendingSlashPrefix) }
func EpochAuthorizationPrefix() []byte        { return JoinLenPrefix(epochAuthorizationPrefix) }
func PendingEpochAuthorizationPrefix() []byte { return JoinLenPrefix(pendingEpochAuthorizationPrefix) }
func BridgeMintPrefix() []byte                { return JoinLenPrefix(bridgeMintPrefix) }
func BridgeBurnPrefix() []byte                { return JoinLenPrefix(bridgeBurnPrefix) }
func PendingBridgeBurnPrefix() []byte         { return JoinLenPrefix(pendingBridgeBurnPrefix) }
func KeyForValidatorHandoffManifest() []byte  { return JoinLenPrefix(handoffManifestPrefix) }
func KeyForValidatorHandoffManifestRoot(root []byte) []byte {
	return JoinLenPrefix(handoffManifestPrefix, root)
}
func KeyForDomainRotationState(domainID []byte) []byte {
	return JoinLenPrefix(domainRotationStatePrefix, domainID)
}
func KeyForValidatorHandoffCancellationManifest() []byte {
	return JoinLenPrefix(handoffCancellationManifestPrefix)
}
func KeyForValidatorHandoffCancellationManifestRoot(root []byte) []byte {
	return JoinLenPrefix(handoffCancellationManifestPrefix, root)
}

func KeyForAccount(address []byte) []byte   { return JoinLenPrefix(accountPrefix, address) }
func KeyForValidator(address []byte) []byte { return JoinLenPrefix(validatorPrefix, address) }
func ValidatorPrefix() []byte               { return JoinLenPrefix(validatorPrefix) }
func KeyForFeePool(chainID uint64) []byte {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, chainID)
	return JoinLenPrefix(poolPrefix, encoded)
}
func KeyForEnclave(keyID string) []byte    { return JoinLenPrefix(enclavePrefix, []byte(keyID)) }
func KeyForServicer(address []byte) []byte { return JoinLenPrefix(servicerPrefix, address) }
func KeyForActiveServicer(address []byte) []byte {
	return JoinLenPrefix(activeServicerIndexPrefix, address)
}
func KeyForRequest(requestID string) []byte { return JoinLenPrefix(requestPrefix, []byte(requestID)) }
func KeyForAssignmentIndex(owner []byte, requestID string) []byte {
	return JoinLenPrefix(assignmentIndexPrefix, owner, []byte(requestID))
}
func KeyForSettlementIndex(requestID string) []byte {
	return JoinLenPrefix(settlementIndexPrefix, []byte(requestID))
}
func KeyForExecution(executionID string) []byte {
	return JoinLenPrefix(executionPrefix, []byte(executionID))
}
func KeyForObservation(kind byte, validatorSetID, epoch uint64, subjectHash, observer []byte) []byte {
	return JoinLenPrefix(observationPrefix, []byte{kind}, uint64Bytes(validatorSetID), uint64Bytes(epoch), subjectHash, observer)
}
func ObservationSubjectPrefix(kind byte, validatorSetID, epoch uint64, subjectHash []byte) []byte {
	return JoinLenPrefix(observationPrefix, []byte{kind}, uint64Bytes(validatorSetID), uint64Bytes(epoch), subjectHash)
}
func KeyForObservationClaim(kind byte, validatorSetID, epoch uint64, claimHash, observer []byte) []byte {
	return JoinLenPrefix(observationClaimPrefix, []byte{kind}, uint64Bytes(validatorSetID), uint64Bytes(epoch), claimHash, observer)
}
func KeyForBlockAnchor() []byte { return JoinLenPrefix(blockAnchorPrefix) }
func KeyForQuorumProof(proofID []byte) []byte {
	return JoinLenPrefix(quorumProofPrefix, proofID)
}
func KeyForConsensusCertificate(kind string, key, digest []byte) []byte {
	return JoinLenPrefix(consensusCertificatePrefix, []byte(kind), key, digest)
}
func ConsensusCertificateIdentityPrefix(kind string, key []byte) []byte {
	return JoinLenPrefix(consensusCertificatePrefix, []byte(kind), key)
}
func KeyForRotationProofIndex(domainID []byte, oldSetID, newSetID uint64) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("proof"), domainID, uint64Bytes(oldSetID), uint64Bytes(newSetID))
}
func KeyForQueuedRotationIndex(domainID []byte, oldSetID, newSetID uint64) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("queued"), domainID, uint64Bytes(oldSetID), uint64Bytes(newSetID))
}
func KeyForRotationCancellationIndex(domainID []byte, oldSetID, newSetID uint64) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("cancel"), domainID, uint64Bytes(oldSetID), uint64Bytes(newSetID))
}
func KeyForRotationResolutionIndex(domainID []byte, oldSetID, newSetID uint64) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("resolved"), domainID, uint64Bytes(oldSetID), uint64Bytes(newSetID))
}
func KeyForSettlementDomainAuthority(domainID []byte, validatorSetID uint64) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("authority"), domainID, uint64Bytes(validatorSetID))
}
func KeyForSettlementDomainDeactivation(domainID []byte) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("domain-deactivated"), domainID)
}
func KeyForSettlementDomainDeactivationEpoch(domainID []byte) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("domain-deactivated-epoch"), domainID)
}
func KeyForSettlementDomainRetirementCancellation(domainID, generation []byte) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("domain-retirement-cancelled"), domainID, generation)
}
func KeyForSettlementDomainRetirement(domainID []byte) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("domain-retired"), domainID)
}
func KeyForSettlementDomainLifecycleIntent(domainID []byte) []byte {
	return JoinLenPrefix(rotationProofIndexPrefix, []byte("domain-lifecycle-intent"), domainID)
}
func KeyForQuorumShare(proofID, observer []byte) []byte {
	return JoinLenPrefix(quorumSharePrefix, proofID, observer)
}
func QuorumShareProofPrefix(proofID []byte) []byte {
	return JoinLenPrefix(quorumSharePrefix, proofID)
}
func KeyForDeposit(domainID, chainTxHash []byte) []byte {
	return JoinLenPrefix(depositPrefix, domainID, chainTxHash)
}
func KeyForCredit(domainID, requester []byte) []byte {
	return JoinLenPrefix(creditPrefix, domainID, requester)
}
func KeyForReservation(domainID []byte, requestID string) []byte {
	return JoinLenPrefix(reservationPrefix, domainID, []byte(requestID))
}
func KeyForProvisionalReservation(domainID, requester []byte, requestID string) []byte {
	return JoinLenPrefix(provisionalReservationIndexPrefix, domainID, requester, []byte(requestID))
}
func KeyForProtocolParams() []byte          { return JoinLenPrefix(protocolParamsPrefix) }
func KeyForStakeChange(owner []byte) []byte { return JoinLenPrefix(stakeChangePrefix, owner) }
func KeyForUnbonding(owner []byte, sequence uint64) []byte {
	return JoinLenPrefix(unbondingPrefix, owner, uint64Bytes(sequence))
}
func UnbondingOwnerPrefix(owner []byte) []byte { return JoinLenPrefix(unbondingPrefix, owner) }
func KeyForSlashEvidence(evidenceID []byte) []byte {
	return JoinLenPrefix(slashEvidencePrefix, evidenceID)
}
func KeyForPendingSlash(effectiveEpoch uint64, evidenceID []byte) []byte {
	return JoinLenPrefix(pendingSlashPrefix, uint64Bytes(effectiveEpoch), evidenceID)
}
func KeyForProducerPayout(owner []byte) []byte { return JoinLenPrefix(producerPayoutPrefix, owner) }
func KeyForProducer(epoch uint64, owner []byte) []byte {
	return JoinLenPrefix(producerPrefix, uint64Bytes(epoch), owner)
}
func KeyForProducerIdentity(owner []byte) []byte {
	return JoinLenPrefix(producerIdentityPrefix, owner)
}
func KeyForEpochAuthorization(epoch uint64) []byte {
	return JoinLenPrefix(epochAuthorizationPrefix, uint64Bytes(epoch))
}
func KeyForPendingEpochAuthorization(epoch uint64) []byte {
	return JoinLenPrefix(pendingEpochAuthorizationPrefix, uint64Bytes(epoch))
}
func KeyForLatestEpoch() []byte { return JoinLenPrefix(latestEpochPrefix) }
func KeyForEpochClock() []byte  { return JoinLenPrefix(epochClockPrefix) }
func KeyForEpochValidator(epoch uint64, owner []byte) []byte {
	return JoinLenPrefix(epochValidatorPrefix, uint64Bytes(epoch), owner)
}
func KeyForBridgeState() []byte                 { return JoinLenPrefix(bridgeStatePrefix) }
func KeyForBridgeMint(baseTxHash []byte) []byte { return JoinLenPrefix(bridgeMintPrefix, baseTxHash) }
func KeyForBridgeNonce(nonce uint64) []byte {
	return JoinLenPrefix(bridgeNoncePrefix, uint64Bytes(nonce))
}
func KeyForBridgeBurn(burnID []byte) []byte { return JoinLenPrefix(bridgeBurnPrefix, burnID) }
func KeyForPendingBridgeBurn(burnID []byte) []byte {
	return JoinLenPrefix(pendingBridgeBurnPrefix, burnID)
}

func (c *Contract) read(key []byte, destination proto.Message) (bool, *PluginError) {
	response, err := c.plugin.StateRead(c, &PluginStateReadRequest{Keys: []*PluginKeyRead{{QueryId: 1, Key: key}}})
	if err != nil {
		return false, err
	}
	if response.Error != nil {
		return false, response.Error
	}
	if len(response.Results) != 1 || len(response.Results[0].Entries) == 0 || len(response.Results[0].Entries[0].Value) == 0 {
		return false, nil
	}
	if err = Unmarshal(response.Results[0].Entries[0].Value, destination); err != nil {
		return false, err
	}
	return true, nil
}

func (c *Contract) readStaged(records map[string]proto.Message, key []byte, destination proto.Message) (bool, *PluginError) {
	if staged, ok := records[string(key)]; ok {
		encoded, err := Marshal(staged)
		if err != nil {
			return false, err
		}
		if err = Unmarshal(encoded, destination); err != nil {
			return false, err
		}
		return true, nil
	}
	return c.read(key, destination)
}

type stateRecordFactory func() proto.Message

// prefetchStateRecords resolves many independent point reads through bounded
// plugin IPC calls. Missing keys are cached as nil so staged transaction code
// does not fall back to one synchronous StateRead per absent record.
func (c *Contract) prefetchStateRecords(factories map[string]stateRecordFactory) (map[string]proto.Message, *PluginError) {
	encodedKeys := make([]string, 0, len(factories))
	for encodedKey := range factories {
		encodedKeys = append(encodedKeys, encodedKey)
	}
	sort.Strings(encodedKeys)

	loaded := make(map[string]proto.Message, len(encodedKeys))
	targets := make(map[uint64]string, len(encodedKeys))
	keys := make([]*PluginKeyRead, 0, len(encodedKeys))
	for index, encodedKey := range encodedKeys {
		queryID := uint64(index + 1)
		loaded[encodedKey] = nil
		targets[queryID] = encodedKey
		keys = append(keys, &PluginKeyRead{QueryId: queryID, Key: []byte(encodedKey)})
	}

	// Point reads are already bounded by the transaction cohort limits. Keep a
	// whole authorization cohort in one plugin/FSM exchange instead of paying
	// three Unix-socket round trips for the same height-pinned snapshot.
	const pageSize = 1024
	for start := 0; start < len(keys); start += pageSize {
		end := min(start+pageSize, len(keys))
		response, err := c.plugin.StateRead(c, &PluginStateReadRequest{Keys: keys[start:end]})
		if err != nil {
			return nil, err
		}
		if response.Error != nil {
			return nil, response.Error
		}
		for _, result := range response.Results {
			encodedKey, exists := targets[result.QueryId]
			if !exists || len(result.Entries) == 0 || len(result.Entries[0].Value) == 0 {
				continue
			}
			destination := factories[encodedKey]()
			if err = Unmarshal(result.Entries[0].Value, destination); err != nil {
				return nil, err
			}
			loaded[encodedKey] = destination
		}
	}
	return loaded, nil
}

func (c *Contract) rangeRead(prefix []byte) ([]*PluginStateEntry, *PluginError) {
	const pageSize uint64 = 5000
	var entries []*PluginStateEntry
	var startAfter []byte
	for {
		response, err := c.plugin.StateRead(c, &PluginStateReadRequest{Ranges: []*PluginRangeRead{{
			QueryId: 1, Prefix: prefix, Limit: pageSize, StartAfter: startAfter,
		}}})
		if err != nil {
			return nil, err
		}
		if response.Error != nil {
			return nil, response.Error
		}
		if len(response.Results) != 1 {
			return nil, ErrState("unexpected range response")
		}
		page := response.Results[0].Entries
		for index, entry := range page {
			if entry == nil || !bytes.HasPrefix(entry.Key, prefix) ||
				(len(startAfter) != 0 && bytes.Compare(entry.Key, startAfter) <= 0) ||
				(index > 0 && bytes.Compare(entry.Key, page[index-1].Key) <= 0) {
				return nil, ErrState("range response is not a strictly ordered continuation")
			}
		}
		entries = append(entries, page...)
		if uint64(len(page)) < pageSize {
			return entries, nil
		}
		startAfter = append(startAfter[:0], page[len(page)-1].Key...)
	}
}

func (c *Contract) rangeReadPage(prefix, startAfter []byte, limit uint64) ([]*PluginStateEntry, *PluginError) {
	if limit == 0 || limit > 5000 {
		return nil, ErrInvalidTransaction("range page limit must be between one and 5000")
	}
	response, err := c.plugin.StateRead(c, &PluginStateReadRequest{Ranges: []*PluginRangeRead{{
		QueryId: 1, Prefix: prefix, Limit: limit, StartAfter: startAfter,
	}}})
	if err != nil {
		return nil, err
	}
	if response.Error != nil {
		return nil, response.Error
	}
	if len(response.Results) != 1 {
		return nil, ErrState("unexpected range response")
	}
	page := response.Results[0].Entries
	for index, entry := range page {
		if entry == nil || !bytes.HasPrefix(entry.Key, prefix) ||
			(len(startAfter) != 0 && bytes.Compare(entry.Key, startAfter) <= 0) ||
			(index > 0 && bytes.Compare(entry.Key, page[index-1].Key) <= 0) {
			return nil, ErrState("range response is not a strictly ordered continuation")
		}
	}
	return page, nil
}

func (c *Contract) write(records map[string]proto.Message) *PluginError {
	return c.writeChanges(records, nil)
}

func (c *Contract) writeChanges(records map[string]proto.Message, deletes [][]byte) *PluginError {
	keys := sortedRecordKeys(records)
	request := &PluginStateWriteRequest{}
	for _, key := range keys {
		encoded, err := Marshal(records[key])
		if err != nil {
			return err
		}
		request.Sets = append(request.Sets, &PluginSetOp{Key: []byte(key), Value: encoded})
	}
	sort.Slice(deletes, func(i, j int) bool { return string(deletes[i]) < string(deletes[j]) })
	for _, key := range deletes {
		request.Deletes = append(request.Deletes, &PluginDeleteOp{Key: key})
	}
	response, err := c.plugin.StateWrite(c, request)
	if err != nil {
		return err
	}
	return response.Error
}

func sortedRecordKeys(records map[string]proto.Message) []string {
	keys := make([]string, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func activeAssignmentOwners(request *RequestRecord) map[string][]byte {
	result := make(map[string][]byte)
	if request == nil || request.Status != "authorized" {
		return result
	}
	for _, assignment := range request.Assignments {
		if assignment == nil || assignment.Completed || assignment.TerminalStatus == "awaiting_servicer" || len(assignment.ServicerAddress) != 20 {
			continue
		}
		result[string(assignment.ServicerAddress)] = append([]byte(nil), assignment.ServicerAddress...)
	}
	return result
}

func stageAssignmentIndexes(records map[string]proto.Message, request *RequestRecord, previous map[string][]byte) [][]byte {
	current := activeAssignmentOwners(request)
	deletes := make([][]byte, 0, len(previous))
	for key, owner := range previous {
		if _, retained := current[key]; !retained {
			deletes = append(deletes, KeyForAssignmentIndex(owner, request.RequestId))
		}
	}
	for _, owner := range current {
		records[string(KeyForAssignmentIndex(owner, request.RequestId))] = &RequestRecord{RequestId: request.RequestId}
	}
	return deletes
}

func hashFields(fields ...[]byte) []byte {
	h := sha256.New()
	var length [8]byte
	for _, field := range fields {
		binary.BigEndian.PutUint64(length[:], uint64(len(field)))
		_, _ = h.Write(length[:])
		_, _ = h.Write(field)
	}
	return h.Sum(nil)
}

func uint64Bytes(value uint64) []byte {
	result := make([]byte, 8)
	binary.BigEndian.PutUint64(result, value)
	return result
}

func uint32Bytes(value uint32) []byte {
	result := make([]byte, 4)
	binary.BigEndian.PutUint32(result, value)
	return result
}

func mulDiv64(left, right, divisor uint64) (uint64, bool) {
	if divisor == 0 {
		return 0, false
	}
	value := new(big.Int).Mul(new(big.Int).SetUint64(left), new(big.Int).SetUint64(right))
	value.Div(value, new(big.Int).SetUint64(divisor))
	return value.Uint64(), value.IsUint64()
}

func stringListBytes(values []string) []byte {
	fields := make([][]byte, len(values))
	for index := range values {
		fields[index] = []byte(values[index])
	}
	return hashFields(fields...)
}
