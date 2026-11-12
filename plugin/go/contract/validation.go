package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

const addressSize = 20

func validAddress(address []byte) bool { return len(address) == addressSize }

func validPayoutAddress(address []byte) bool {
	if !validAddress(address) {
		return false
	}
	for _, value := range address {
		if value != 0 {
			return true
		}
	}
	return false
}

func validSettlementPayouts(payouts []*SettlementPayout) bool {
	if len(payouts) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(payouts))
	for _, payout := range payouts {
		if payout == nil || !validHash(payout.SettlementDomainId) || !validPayoutAddress(payout.Address) {
			return false
		}
		key := string(payout.SettlementDomainId)
		if _, duplicate := seen[key]; duplicate {
			return false
		}
		seen[key] = struct{}{}
	}
	return true
}
func validHash(hash []byte) bool { return len(hash) == sha256.Size }

func validModels(models []string) bool {
	if len(models) == 0 || len(models) > 7 {
		return false
	}
	seen := make(map[string]struct{}, len(models))
	for _, model := range models {
		if strings.TrimSpace(model) != model || model == "" || len(model) > 200 {
			return false
		}
		if _, exists := seen[model]; exists {
			return false
		}
		seen[model] = struct{}{}
	}
	return true
}

func validOutputType(outputType string) bool {
	switch outputType {
	case "boolean", "score", "choice", "private_hash":
		return true
	default:
		return false
	}
}

func checkObserveEnclave(message *MessageObserveEnclave) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validAddress(message.OwnerAddress) ||
		len(message.PublicKey) != ed25519.PublicKeySize || !validHash(message.AttestationHash) ||
		!validPCRMeasurements(message.Pcr0, message.Pcr1, message.Pcr2) ||
		len(message.Nonce) == 0 || len(message.Nonce) > 64 || len(message.UserData) > 1024 ||
		len(message.ProofSignature) != ed25519.SignatureSize {
		return nil, ErrInvalidTransaction("invalid enclave observation")
	}
	if len(message.AttestationDocument) > 1<<20 {
		return nil, ErrInvalidTransaction("enclave attestation document is too large")
	}
	if len(message.AttestationDocument) != 0 {
		digest := sha256.Sum256(message.AttestationDocument)
		if !bytes.Equal(digest[:], message.AttestationHash) {
			return nil, ErrInvalidTransaction("enclave attestation document hash mismatch")
		}
	}
	keyDigest := sha256.Sum256(message.PublicKey)
	if message.TeeKeyId != "ed25519:"+hex.EncodeToString(keyDigest[:]) {
		return nil, ErrInvalidTransaction("TEE key identifier does not match its public key")
	}
	registrationDigest := sha256.New()
	_, _ = registrationDigest.Write([]byte("takusen:nitro-registration\x00"))
	_, _ = registrationDigest.Write(message.Nonce)
	_, _ = registrationDigest.Write([]byte{0})
	_, _ = registrationDigest.Write(message.UserData)
	if !ed25519.Verify(message.PublicKey, registrationDigest.Sum(nil), message.ProofSignature) {
		return nil, ErrCrypto("invalid enclave proof of possession")
	}
	return message.ObserverAddress, nil
}

func checkRevokeEnclave(message *MessageRevokeEnclave) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.TeeKeyId == "" || len(message.TeeKeyId) > 128 {
		return nil, ErrInvalidTransaction("invalid enclave revocation")
	}
	return message.ObserverAddress, nil
}

func checkRegisterServicer(message *MessageRegisterServicer) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) || !validSettlementPayouts(message.Payouts) || message.TeeKeyId == "" || message.Bond == 0 || !validModels(message.Models) {
		return nil, ErrInvalidTransaction("invalid servicer registration")
	}
	return message.OwnerAddress, nil
}

func checkUpdateServicer(message *MessageUpdateServicer) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) || !validSettlementPayouts(message.Payouts) || message.TeeKeyId == "" ||
		!validModels(message.Models) {
		return nil, ErrInvalidTransaction("invalid servicer update")
	}
	return message.OwnerAddress, nil
}

func checkObserveDeposit(message *MessageObserveDeposit) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validHash(message.SettlementDomainId) || !validHash(message.ChainTxHash) ||
		!validAddress(message.Requester) || message.AmountMicros == 0 || len(message.TokenAmount) == 0 || len(message.TokenAmount) > 32 {
		return nil, ErrInvalidTransaction("invalid settlement deposit observation")
	}
	return message.ObserverAddress, nil
}

func checkResolveDeposit(message *MessageResolveDeposit) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validHash(message.SettlementDomainId) || !validHash(message.ChainTxHash) ||
		(message.Resolution != "finalized" && message.Resolution != "reorged") {
		return nil, ErrInvalidTransaction("invalid settlement deposit resolution")
	}
	return message.ObserverAddress, nil
}

func checkResolveSettlement(message *MessageResolveSettlement) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validHash(message.SettlementDomainId) || message.RequestId == "" || len(message.RequestId) > 128 ||
		!validHash(message.SettlementTxHash) || len(message.ExecutionIds) == 0 {
		return nil, ErrInvalidTransaction("invalid settlement reorg resolution")
	}
	seen := make(map[string]struct{}, len(message.ExecutionIds))
	for _, executionID := range message.ExecutionIds {
		if executionID == "" {
			return nil, ErrInvalidTransaction("invalid settlement reorg execution")
		}
		if _, duplicate := seen[executionID]; duplicate {
			return nil, ErrInvalidTransaction("duplicate settlement reorg execution")
		}
		seen[executionID] = struct{}{}
	}
	return message.ObserverAddress, nil
}

func checkObserveAuthorization(message *MessageObserveAuthorization) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validHash(message.SettlementDomainId) || message.RequestId == "" || len(message.RequestId) > 128 ||
		!validHash(message.InputHash) || !validAddress(message.Requester) || message.ReservedBudget == 0 ||
		!validOutputType(message.OutputType) || !validModels(message.Models) || message.ExecutionQuorum == 0 ||
		!validRequestOutputSchema(message) ||
		int(message.ExecutionQuorum) > len(message.Models) || message.DeadlineHeight == 0 ||
		len(message.AuthorizationSignature) == 0 || message.AuthorizationDeadline == 0 ||
		((message.AuthorizationChainBlockNumber == 0) != (len(message.AuthorizationChainBlockHash) == 0)) ||
		(len(message.AuthorizationChainBlockHash) != 0 && len(message.AuthorizationChainBlockHash) != 32) ||
		!validArchiveID(message.RequestArchiveId) || message.RequestArchiveId != "sha256:"+hex.EncodeToString(message.InputHash) {
		return nil, ErrInvalidTransaction("invalid signed request authorization observation")
	}
	return message.ObserverAddress, nil
}

func validRequestOutputSchema(message *MessageObserveAuthorization) bool {
	if !validHash(message.SchemaHash) {
		return false
	}
	valid := false
	switch message.OutputType {
	case "boolean":
		valid = message.OutputMinimum == 0 && message.OutputMaximum == 1 && len(message.OutputChoices) == 0
	case "score":
		valid = message.OutputMinimum >= 0 && message.OutputMaximum <= 100 && message.OutputMinimum < message.OutputMaximum && len(message.OutputChoices) == 0
	case "choice":
		if len(message.OutputChoices) < 2 || len(message.OutputChoices) > 26 || message.OutputMinimum != int64('A') || message.OutputMaximum != int64('A'+len(message.OutputChoices)-1) {
			return false
		}
		seen := make(map[string]struct{}, len(message.OutputChoices))
		for _, choice := range message.OutputChoices {
			if choice == "" || choice != strings.TrimSpace(choice) || len(choice) > 256 {
				return false
			}
			if _, exists := seen[choice]; exists {
				return false
			}
			seen[choice] = struct{}{}
		}
		valid = true
	case "private_hash":
		valid = message.OutputMinimum == 0 && message.OutputMaximum == 0 && len(message.OutputChoices) == 0
	default:
		return false
	}
	return valid && bytes.Equal(message.SchemaHash, requestOutputSchemaHash(message))
}

func requestOutputSchemaHash(message *MessageObserveAuthorization) []byte {
	var outputType uint64
	switch message.OutputType {
	case "boolean":
		outputType = 1
	case "score":
		outputType = 2
	case "choice":
		outputType = 3
	case "private_hash":
		outputType = 4
	}
	choicesHash := make([]byte, 32)
	if len(message.OutputChoices) != 0 {
		choicesHash = legacyKeccak256(abiEncodeStrings(message.OutputChoices))
	}
	encoded := make([]byte, 0, 128)
	encoded = append(encoded, abiUintWord(outputType)...)
	encoded = append(encoded, abiUintWord(uint64(message.OutputMinimum))...)
	encoded = append(encoded, abiUintWord(uint64(message.OutputMaximum))...)
	encoded = append(encoded, choicesHash...)
	return legacyKeccak256(encoded)
}

func abiEncodeStrings(values []string) []byte {
	encoded := make([]byte, 0, 64+len(values)*96)
	encoded = append(encoded, abiUintWord(32)...)
	encoded = append(encoded, abiUintWord(uint64(len(values)))...)
	offset := uint64(len(values) * 32)
	for _, value := range values {
		encoded = append(encoded, abiUintWord(offset)...)
		offset += uint64(32 + ((len(value)+31)/32)*32)
	}
	for _, value := range values {
		encoded = append(encoded, abiUintWord(uint64(len(value)))...)
		encoded = append(encoded, []byte(value)...)
		encoded = append(encoded, make([]byte, (32-len(value)%32)%32)...)
	}
	return encoded
}

func abiUintWord(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}

func legacyKeccak256(value []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(value)
	return hasher.Sum(nil)
}

func checkObserveAuthorizations(message *MessageObserveAuthorizations) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || len(message.Authorizations) == 0 || len(message.Authorizations) > 1024 {
		return nil, ErrInvalidTransaction("invalid signed request authorization batch")
	}
	seen := make(map[string]struct{}, len(message.Authorizations))
	for _, authorization := range message.Authorizations {
		if authorization == nil || !bytes.Equal(authorization.ObserverAddress, message.ObserverAddress) {
			return nil, ErrInvalidTransaction("authorization batch observer does not match its item")
		}
		if _, err := checkObserveAuthorization(authorization); err != nil {
			return nil, err
		}
		if _, duplicate := seen[authorization.RequestId]; duplicate {
			return nil, ErrInvalidTransaction("authorization batch contains a duplicate request")
		}
		seen[authorization.RequestId] = struct{}{}
	}
	return message.ObserverAddress, nil
}

func checkQueueAuthorization(message *MessageQueueAuthorization) ([]byte, *PluginError) {
	if message == nil || !validAddress(message.RelayerAddress) || message.Authorization == nil {
		return nil, ErrInvalidTransaction("invalid queued request authorization")
	}
	authorization := message.Authorization
	if authorization.DirectEoa || len(authorization.ObserverAddress) != 0 || authorization.AuthorizationChainBlockNumber == 0 ||
		len(authorization.AuthorizationChainBlockHash) != 32 {
		return nil, ErrInvalidTransaction("queued authorization must contain pinned ERC-1271 evidence without an observer")
	}
	copy := proto.Clone(authorization).(*MessageObserveAuthorization)
	copy.ObserverAddress = message.RelayerAddress
	if _, err := checkObserveAuthorization(copy); err != nil {
		return nil, err
	}
	return message.RelayerAddress, nil
}

func checkSubmitExecution(message *MessageSubmitExecution) ([]byte, *PluginError) {
	if !validAddress(message.ServicerAddress) || len(message.PublicKey) != ed25519.PublicKeySize || !validExecutionItem(message) {
		return nil, ErrInvalidTransaction("invalid execution submission")
	}
	return message.ServicerAddress, nil
}

func validExecutionItem(message *MessageSubmitExecution) bool {
	return message != nil && len(message.ReceiptJson) != 0 && len(message.ReceiptJson) <= 64*1024 &&
		len(message.Signature) == ed25519.SignatureSize
}

func checkSubmitExecutions(message *MessageSubmitExecutions) ([]byte, *PluginError) {
	if !validAddress(message.ServicerAddress) || len(message.PublicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidTransaction("invalid execution submission batch")
	}
	if len(message.CompressedExecutions) != 0 {
		if len(message.Executions) != 0 {
			return nil, ErrInvalidTransaction("compressed execution batch is invalid")
		}
		if err := checkCompressedExecutionEnvelope(message.CompressedExecutions); err != nil {
			return nil, err
		}
		return message.ServicerAddress, nil
	}
	if err := validateExecutionBatchItems(message); err != nil {
		return nil, err
	}
	return message.ServicerAddress, nil
}

func validateExecutionBatchItems(message *MessageSubmitExecutions) *PluginError {
	if len(message.Executions) == 0 || len(message.Executions) > 256 {
		return ErrInvalidTransaction("invalid execution submission batch")
	}
	seen := make(map[string]struct{}, len(message.Executions))
	receiptBytes := 0
	for _, execution := range message.Executions {
		if !validExecutionItem(execution) || len(execution.ServicerAddress) != 0 || len(execution.PublicKey) != 0 || execution.ArchiveId != "" {
			return ErrInvalidTransaction("execution batch servicer does not match its receipt")
		}
		receiptBytes += len(execution.ReceiptJson) + len(execution.Signature)
		if receiptBytes > maxExpandedExecutionBatch {
			return ErrInvalidTransaction("execution batch receipt bytes exceed the safety limit")
		}
		key := string(execution.ReceiptJson)
		if _, duplicate := seen[key]; duplicate {
			return ErrInvalidTransaction("execution submission batch contains a duplicate receipt")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func checkReassignRequest(message *MessageReassignRequest) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.RequestId == "" || message.Model == "" || message.NewDeadlineHeight == 0 {
		return nil, ErrInvalidTransaction("invalid reassignment")
	}
	return message.ObserverAddress, nil
}

func checkFinalizeRequest(message *MessageFinalizeRequest) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validHash(message.SettlementDomainId) || message.RequestId == "" || len(message.ExecutionIds) == 0 || message.RequestSpent > message.ReservedBudget ||
		!validHash(message.SettlementTxHash) {
		return nil, ErrInvalidTransaction("invalid settlement finalization")
	}
	certificateFields := 0
	if message.ValidatorSetId != 0 {
		certificateFields++
	}
	if len(message.SignerBitmap) != 0 {
		certificateFields++
	}
	if len(message.AggregateSignature) != 0 {
		certificateFields++
	}
	if certificateFields != 0 && certificateFields != 3 {
		return nil, ErrInvalidTransaction("incomplete settlement finalization certificate")
	}
	return message.ObserverAddress, nil
}

func checkFinalizeRequests(message *MessageFinalizeRequests) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || len(message.Requests) == 0 || len(message.Requests) > 512 ||
		message.ValidatorSetId == 0 || len(message.SignerBitmap) == 0 || len(message.AggregateSignature) == 0 {
		return nil, ErrInvalidTransaction("invalid settlement finalization batch")
	}
	seen := make(map[string]struct{}, len(message.Requests))
	for _, request := range message.Requests {
		if request == nil || !validHash(request.SettlementDomainId) || request.RequestId == "" || request.ReservedBudget == 0 || len(request.ExecutionIds) == 0 || request.RequestSpent > request.ReservedBudget ||
			!validHash(request.SettlementTxHash) || len(request.ObserverAddress) != 0 || request.ValidatorSetId != 0 ||
			len(request.SignerBitmap) != 0 || len(request.AggregateSignature) != 0 {
			return nil, ErrInvalidTransaction("invalid settlement finalization batch member")
		}
		if _, duplicate := seen[request.RequestId]; duplicate {
			return nil, ErrInvalidTransaction("duplicate settlement finalization batch member")
		}
		seen[request.RequestId] = struct{}{}
	}
	return message.ObserverAddress, nil
}

func checkSubmitQuorumSignature(message *MessageSubmitQuorumSignature) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.ProofKind == "" || len(message.ProofKind) > 64 ||
		!validHash(message.ProofId) || !validHash(message.Digest) || !validHash(message.Message) ||
		message.ValidatorSetId == 0 || len(message.Signature) != 96 {
		return nil, ErrInvalidTransaction("invalid quorum signature share")
	}
	if !strings.EqualFold(hex.EncodeToString(message.Message), hex.EncodeToString(message.Digest)) {
		return nil, ErrInvalidTransaction("quorum message digest mismatch")
	}
	expectedID := quorumProofID(message.ProofKind, message.ValidatorSetId, message.Digest)
	if !strings.EqualFold(hex.EncodeToString(expectedID), hex.EncodeToString(message.ProofId)) {
		return nil, ErrInvalidTransaction("quorum proof identifier mismatch")
	}
	return message.ObserverAddress, nil
}

func checkObserveBridgeLock(message *MessageObserveBridgeLock) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validHash(message.CanonicalChainTxHash) || message.Nonce == 0 ||
		!validAddress(message.CanonicalChainSender) || !validAddress(message.Recipient) || message.Amount == 0 {
		return nil, ErrInvalidTransaction("invalid Base bridge lock observation")
	}
	return message.ObserverAddress, nil
}

func checkObserveBridgeRelease(message *MessageObserveBridgeRelease) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validHash(message.BurnId) || !validHash(message.CanonicalChainTxHash) ||
		message.Nonce == 0 || !validAddress(message.CanonicalChainRecipient) || message.Amount == 0 || message.ValidatorSetId == 0 {
		return nil, ErrInvalidTransaction("invalid Base bridge release observation")
	}
	return message.ObserverAddress, nil
}

func checkObserveEpochMint(message *MessageObserveEpochMint) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || message.Epoch == 0 || !validHash(message.CanonicalChainTxHash) || message.ValidatorSetId == 0 {
		return nil, ErrInvalidTransaction("invalid epoch mint observation")
	}
	return message.ObserverAddress, nil
}

func checkBurnBridge(message *MessageBurnBridge) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) || !validAddress(message.CanonicalChainRecipient) ||
		message.Amount == 0 || !validHash(message.BurnId) {
		return nil, ErrInvalidTransaction("invalid Canopy bridge burn")
	}
	return message.OwnerAddress, nil
}

func checkQueueServicerStake(message *MessageQueueServicerStake) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) {
		return nil, ErrInvalidTransaction("invalid queued servicer stake change")
	}
	return message.OwnerAddress, nil
}

func checkWithdrawUnbonded(message *MessageWithdrawUnbonded) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) || message.Sequence == 0 {
		return nil, ErrInvalidTransaction("invalid unbonding withdrawal")
	}
	return message.OwnerAddress, nil
}

func checkSetProducerPayout(message *MessageSetProducerPayout) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) || !validAddress(message.CanonicalChainAddress) {
		return nil, ErrInvalidTransaction("invalid producer payout address")
	}
	return message.OwnerAddress, nil
}

func checkObserveSlashEvidence(message *MessageObserveSlashEvidence) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || !validHash(message.EvidenceId) ||
		!validAddress(message.TargetAddress) || (message.Reason != "timeout" && message.Reason != "invalid_receipt") {
		return nil, ErrInvalidTransaction("invalid servicer slash evidence")
	}
	return message.ObserverAddress, nil
}
