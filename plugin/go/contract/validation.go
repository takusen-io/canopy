package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/sha3"
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

func validHash(hash []byte) bool { return len(hash) == sha256.Size }

func validModels(models []*ServicerModelPolicy) bool {
	if len(models) == 0 || len(models) > 7 {
		return false
	}
	previous := ""
	for _, item := range models {
		if item == nil || item.Model == "" || strings.TrimSpace(item.Model) != item.Model || len(item.Model) > 200 || item.MinimumAcceptableBudget == 0 || item.Model <= previous {
			return false
		}
		previous = item.Model
	}
	return true
}

func validRequestModels(models []*ModelBudget, reserved uint64) bool {
	if len(models) == 0 || len(models) > 7 {
		return false
	}
	seen := make(map[string]struct{}, len(models))
	var total uint64
	for _, item := range models {
		if item == nil || strings.TrimSpace(item.Model) != item.Model || item.Model == "" || len(item.Model) > 200 || item.Budget == 0 || ^uint64(0)-total < item.Budget {
			return false
		}
		if _, exists := seen[item.Model]; exists {
			return false
		}
		seen[item.Model] = struct{}{}
		total += item.Budget
	}
	return total == reserved
}

func validOutputType(outputType string) bool {
	switch outputType {
	case "boolean", "score", "choice", "private_hash":
		return true
	default:
		return false
	}
}

func checkRegisterServicer(message *MessageRegisterServicer) ([]byte, *PluginError) {
	if message == nil || !validAddress(message.OwnerAddress) || !validPayoutAddress(message.EvmPayoutAddress) ||
		!validModels(message.Models) || message.Bond == 0 || message.TeeKeyId == "" ||
		len(message.PublicKey) != ed25519.PublicKeySize || len(message.Nonce) < 16 || len(message.Nonce) > 64 ||
		len(message.ProofSignature) != ed25519.SignatureSize || len(message.AttestationDocument) == 0 ||
		len(message.AttestationDocument) > maxNitroAttestationSize || !bytes.Equal(message.UserData, registrationUserData(message.OwnerAddress)) {
		return nil, ErrInvalidTransaction("invalid atomic servicer registration")
	}
	if err := checkAttestedEnclave(message.TeeKeyId, message.PublicKey, message.Nonce, message.UserData, message.ProofSignature); err != nil {
		return nil, err
	}
	return message.OwnerAddress, nil
}

func checkManageServicer(message *MessageManageServicer) ([]byte, *PluginError) {
	if message == nil || !validAddress(message.OwnerAddress) || message.ExpectedRevision == 0 ||
		message.Configuration == nil && message.Bond == nil && message.Rotation == nil {
		return nil, ErrInvalidTransaction("invalid servicer management")
	}
	if update := message.Configuration; update != nil &&
		(!validPayoutAddress(update.EvmPayoutAddress) || !validModels(update.Models)) {
		return nil, ErrInvalidTransaction("invalid servicer configuration update")
	}
	if rotation := message.Rotation; rotation != nil &&
		(rotation.TeeKeyId == "" || len(rotation.TeeKeyId) > 128 || len(rotation.PublicKey) != ed25519.PublicKeySize ||
			len(rotation.Nonce) < 16 || len(rotation.Nonce) > 64 || len(rotation.ProofSignature) != ed25519.SignatureSize ||
			len(rotation.AttestationDocument) == 0 || len(rotation.AttestationDocument) > maxNitroAttestationSize ||
			!bytes.Equal(rotation.UserData, registrationUserData(message.OwnerAddress))) {
		return nil, ErrInvalidTransaction("invalid attested servicer management")
	}
	if rotation := message.Rotation; rotation != nil {
		if err := checkAttestedEnclave(rotation.TeeKeyId, rotation.PublicKey, rotation.Nonce, rotation.UserData, rotation.ProofSignature); err != nil {
			return nil, err
		}
	}
	return message.OwnerAddress, nil
}

func checkBeginServicerUnstake(message *MessageBeginServicerUnstake) ([]byte, *PluginError) {
	if message == nil || !validAddress(message.OwnerAddress) || message.ExpectedRevision == 0 {
		return nil, ErrInvalidTransaction("invalid servicer unstake")
	}
	return message.OwnerAddress, nil
}

func checkEnclaveRevocation(message *EnclaveRevocation) *PluginError {
	if message == nil || message.TeeKeyId == "" || len(message.TeeKeyId) > 128 || len(message.IncidentId) != sha256.Size {
		return ErrInvalidTransaction("invalid enclave revocation candidate")
	}
	return nil
}

func enclaveRevocationDigest(message *EnclaveRevocation) []byte {
	if err := checkEnclaveRevocation(message); err != nil {
		return nil
	}
	return hashFields([]byte("takusen:enclave-revocation:v1"), []byte(message.TeeKeyId), message.IncidentId)
}

func enclaveRevocationKey(message *EnclaveRevocation) []byte {
	if err := checkEnclaveRevocation(message); err != nil {
		return nil
	}
	return hashFields([]byte(message.TeeKeyId), message.IncidentId)
}

func checkAttestedEnclave(teeKeyID string, publicKey, nonce, userData, proofSignature []byte) *PluginError {
	keyDigest := sha256.Sum256(publicKey)
	if teeKeyID != "ed25519:"+hex.EncodeToString(keyDigest[:]) {
		return ErrInvalidTransaction("TEE key identifier does not match its public key")
	}
	registrationDigest := sha256.New()
	_, _ = registrationDigest.Write([]byte("takusen:nitro-registration\x00"))
	_, _ = registrationDigest.Write(nonce)
	_, _ = registrationDigest.Write([]byte{0})
	_, _ = registrationDigest.Write(userData)
	if !ed25519.Verify(publicKey, registrationDigest.Sum(nil), proofSignature) {
		return ErrCrypto("invalid enclave proof of possession")
	}
	return nil
}

func registrationUserData(owner []byte) []byte {
	return []byte("takusen:servicer-registration:v1:" + hex.EncodeToString(owner))
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

func checkAuthorizationItem(message *Authorization) ([]byte, *PluginError) {
	if !validHash(message.SettlementDomainId) || message.RequestId == "" || len(message.RequestId) > 128 ||
		!validHash(message.InputHash) || !validAddress(message.Requester) || message.ReservedBudget == 0 ||
		!validOutputType(message.OutputType) || !validRequestModels(message.Models, message.ReservedBudget) || message.DisplayAgreementThreshold == 0 ||
		!validRequestOutputSchema(message) ||
		int(message.DisplayAgreementThreshold) > len(message.Models) || message.DeadlineHeight == 0 ||
		len(message.AuthorizationSignature) == 0 || message.AuthorizationDeadline == 0 ||
		((message.AuthorizationChainBlockNumber == 0) != (len(message.AuthorizationChainBlockHash) == 0)) ||
		(len(message.AuthorizationChainBlockHash) != 0 && len(message.AuthorizationChainBlockHash) != 32) ||
		!validArchiveID(message.RequestArchiveId) || message.RequestArchiveId != "sha256:"+hex.EncodeToString(message.InputHash) {
		return nil, ErrInvalidTransaction("invalid signed request authorization observation")
	}
	return nil, nil
}

func validRequestOutputSchema(message *Authorization) bool {
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

func requestOutputSchemaHash(message *Authorization) []byte {
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
		choicesHash = ethereumKeccak256(abiEncodeStrings(message.OutputChoices))
	}
	encoded := make([]byte, 0, 128)
	encoded = append(encoded, abiUintWord(outputType)...)
	encoded = append(encoded, abiUintWord(uint64(message.OutputMinimum))...)
	encoded = append(encoded, abiUintWord(uint64(message.OutputMaximum))...)
	encoded = append(encoded, choicesHash...)
	return ethereumKeccak256(encoded)
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

func ethereumKeccak256(value []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(value)
	return hasher.Sum(nil)
}

func checkObserveAuthorizations(message *MessageObserveAuthorizations) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || len(message.Authorizations) == 0 || len(message.Authorizations) > 256 {
		return nil, ErrInvalidTransaction("invalid signed request authorization batch")
	}
	seen := make(map[string]struct{}, len(message.Authorizations))
	for _, authorization := range message.Authorizations {
		if authorization == nil || !authorization.DirectEoa || authorization.AuthorizationChainBlockNumber != 0 || len(authorization.AuthorizationChainBlockHash) != 0 {
			return nil, ErrInvalidTransaction("authorization batch must contain directly verifiable EOA authorizations")
		}
		if _, err := checkAuthorizationItem(authorization); err != nil {
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
	if authorization.DirectEoa || authorization.AuthorizationChainBlockNumber == 0 ||
		len(authorization.AuthorizationChainBlockHash) != 32 {
		return nil, ErrInvalidTransaction("queued authorization must contain pinned ERC-1271 evidence")
	}
	if _, err := checkAuthorizationItem(authorization); err != nil {
		return nil, err
	}
	return message.RelayerAddress, nil
}

func validExecutionItem(message *ExecutionSubmission) bool {
	return message != nil && len(message.ReceiptJson) != 0 && len(message.ReceiptJson) <= 64*1024 &&
		len(message.Signature) == ed25519.SignatureSize
}

func checkSubmitExecutions(message *MessageSubmitExecutions) ([]byte, *PluginError) {
	if !validAddress(message.ServicerAddress) {
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
	if len(message.Executions) == 0 || len(message.Executions) > 128 {
		return ErrInvalidTransaction("invalid execution submission batch")
	}
	seen := make(map[string]struct{}, len(message.Executions))
	receiptBytes := 0
	for _, execution := range message.Executions {
		if !validExecutionItem(execution) {
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

func checkFinalizeRequests(message *MessageFinalizeRequests) ([]byte, *PluginError) {
	if !validAddress(message.ObserverAddress) || len(message.Requests) == 0 || len(message.Requests) > 512 ||
		message.ValidatorSetId == 0 || len(message.SignerBitmap) == 0 || len(message.AggregateSignature) == 0 {
		return nil, ErrInvalidTransaction("invalid settlement finalization batch")
	}
	seen := make(map[string]struct{}, len(message.Requests))
	for _, request := range message.Requests {
		if request == nil || !validHash(request.SettlementDomainId) || request.RequestId == "" || request.ReservedBudget == 0 || len(request.ExecutionIds) == 0 || request.RequestSpent > request.ReservedBudget ||
			!validHash(request.SettlementTxHash) {
			return nil, ErrInvalidTransaction("invalid settlement finalization batch member")
		}
		if _, duplicate := seen[request.RequestId]; duplicate {
			return nil, ErrInvalidTransaction("duplicate settlement finalization batch member")
		}
		seen[request.RequestId] = struct{}{}
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

func checkSetProducerPayout(message *MessageSetProducerPayout) ([]byte, *PluginError) {
	if !validAddress(message.OwnerAddress) || !validAddress(message.CanonicalChainAddress) {
		return nil, ErrInvalidTransaction("invalid producer payout address")
	}
	return message.OwnerAddress, nil
}
