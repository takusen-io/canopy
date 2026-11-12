package contract

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"runtime"
	"sync"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	secpECDSA "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

func keccak(parts ...[]byte) []byte {
	hash := sha3.NewLegacyKeccak256()
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	return hash.Sum(nil)
}

func verifyEOARequestAuthorization(message *MessageObserveAuthorization, params *ProtocolParams) *PluginError {
	domainConfig, domainErr := settlementDomain(params, message.SettlementDomainId, true)
	if domainErr != nil {
		return domainErr
	}
	if len(message.AuthorizationSignature) != 65 || message.AuthorizationDeadline == 0 {
		return ErrUnauthorized("direct EOA authorization requires a governed settlement domain and a recoverable signature")
	}
	signature := append([]byte(nil), message.AuthorizationSignature...)
	recovery := signature[64]
	if recovery >= 27 {
		recovery -= 27
	}
	if recovery > 1 {
		return ErrCrypto("invalid EOA recovery identifier")
	}
	// Match the EVM's low-s rule so the native and contract verifiers accept the
	// same signatures and do not introduce a second malleable representation.
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(secp256k1.S256().Params().N), 1)
	if new(big.Int).SetBytes(signature[32:64]).Cmp(halfOrder) > 0 {
		return ErrCrypto("non-canonical EOA signature")
	}
	domainTypeHash := keccak([]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"))
	domain := keccak(
		domainTypeHash,
		keccak([]byte("Takusen Escrow")),
		keccak([]byte("1")),
		abiUint64(domainConfig.ChainId),
		abiAddress(domainConfig.EscrowAddress),
	)
	requestTypeHash := keccak([]byte("AuthorizeRequest(bytes32 requestId,bytes32 inputHash,bytes32 settlementDomain,address requester,uint128 budget,uint64 deadline)"))
	requestID := sha256.Sum256([]byte(message.RequestId))
	structure := keccak(
		requestTypeHash,
		requestID[:],
		message.InputHash,
		message.SettlementDomainId,
		abiAddress(message.Requester),
		abiUint64(message.ReservedBudget),
		abiUint64(message.AuthorizationDeadline),
	)
	digest := keccak([]byte{0x19, 0x01}, domain, structure)
	compact := make([]byte, 65)
	compact[0] = 27 + recovery
	copy(compact[1:], signature[:64])
	publicKey, _, err := secpECDSA.RecoverCompact(compact, digest)
	if err != nil {
		return ErrCrypto("invalid EOA authorization signature")
	}
	uncompressed := publicKey.SerializeUncompressed()
	address := keccak(uncompressed[1:])[12:]
	if !bytes.Equal(address, message.Requester) {
		return ErrUnauthorized("EOA authorization signer does not match requester")
	}
	return nil
}

// verifyEOARequestAuthorizations uses the host's available cores for the
// independent secp256k1 recoveries in a direct-authorization cohort. Results
// are retained by input index and inspected in request order, so every node
// returns the same first error regardless of goroutine scheduling or CPU count.
func verifyEOARequestAuthorizations(messages []*MessageObserveAuthorization, params *ProtocolParams) *PluginError {
	if len(messages) == 0 {
		return nil
	}
	errs := make([]*PluginError, len(messages))
	workers := min(len(messages), max(1, runtime.GOMAXPROCS(0)))
	jobs := make(chan int, len(messages))
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				errs[index] = verifyEOARequestAuthorization(messages[index], params)
			}
		}()
	}
	for index := range messages {
		jobs <- index
	}
	close(jobs)
	group.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
