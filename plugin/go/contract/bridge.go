package contract

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

const bridgeReleaseType = "BridgeRelease(uint256 chainId,address bridge,uint64 validatorSetId,uint64 nonce,address recipient,uint256 amount,bytes32 canopyBurnId)"

func bridgeLockSubject(message *MessageObserveBridgeLock) []byte {
	return hashFields(
		[]byte("takusen:bridge-lock"), message.CanonicalChainTxHash, uint64Bytes(message.Nonce),
		message.CanonicalChainSender, message.Recipient, uint64Bytes(message.Amount),
	)
}

func (c *Contract) deliverObserveBridgeLock(height uint64, message *MessageObserveBridgeLock) *PluginDeliverResponse {
	if found, err := c.read(KeyForBridgeMint(message.CanonicalChainTxHash), new(BridgeMint)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("Base bridge lock is already minted")}
	}
	if found, err := c.read(KeyForBridgeNonce(message.Nonce), new(ReplayMarker)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("Base bridge lock nonce is already minted")}
	}
	subject := bridgeLockSubject(message)
	claim := hashFields([]byte("bridge-lock"), message.CanonicalChainTxHash, uint64Bytes(message.Nonce))
	observation, reached, err := c.observe(observationBridgeLock, subject, claim, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := observationRecords(observationBridgeLock, subject, claim, message.ObserverAddress, observation)
	if reached {
		params, readErr := c.currentProtocolParams()
		if readErr != nil {
			return &PluginDeliverResponse{Error: readErr}
		}
		if !validAddress(params.CanonicalBridgeAddress) || message.Amount > params.BridgeTransferLimit {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("bridge transfer exceeds governed limits")}
		}
		clock, clockErr := c.currentEpochClock(params)
		if clockErr != nil {
			return &PluginDeliverResponse{Error: clockErr}
		}
		epoch := clock.CurrentEpoch
		state := new(BridgeState)
		found, stateErr := c.read(KeyForBridgeState(), state)
		if stateErr != nil {
			return &PluginDeliverResponse{Error: stateErr}
		}
		if !found || state.MintEpoch != epoch {
			state.MintEpoch, state.MintedInEpoch = epoch, 0
		}
		if ^uint64(0)-state.MintedInEpoch < message.Amount || state.MintedInEpoch+message.Amount > params.BridgeEpochMintLimit {
			return &PluginDeliverResponse{Error: ErrInvalidTransaction("bridge epoch mint limit exceeded")}
		}
		account := new(Account)
		found, accountErr := c.read(KeyForAccount(message.Recipient), account)
		if accountErr != nil {
			return &PluginDeliverResponse{Error: accountErr}
		}
		if !found {
			account.Address = append([]byte(nil), message.Recipient...)
		}
		if !bytes.Equal(account.Address, message.Recipient) || ^uint64(0)-account.Amount < message.Amount {
			return &PluginDeliverResponse{Error: ErrState("bridge recipient account overflow")}
		}
		account.Amount += message.Amount
		state.MintedInEpoch += message.Amount
		records[string(KeyForAccount(message.Recipient))] = account
		records[string(KeyForBridgeState())] = state
		records[string(KeyForBridgeMint(message.CanonicalChainTxHash))] = &BridgeMint{
			CanonicalChainTxHash: append([]byte(nil), message.CanonicalChainTxHash...), Nonce: message.Nonce,
			CanonicalChainSender: append([]byte(nil), message.CanonicalChainSender...), Recipient: append([]byte(nil), message.Recipient...),
			Amount: message.Amount, ObservedHeight: height,
		}
		records[string(KeyForBridgeNonce(message.Nonce))] = &ReplayMarker{Id: append([]byte(nil), message.CanonicalChainTxHash...)}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func (c *Contract) deliverBurnBridge(height uint64, message *MessageBurnBridge) *PluginDeliverResponse {
	if found, err := c.read(KeyForBridgeBurn(message.BurnId), new(BridgeBurn)); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if found {
		return &PluginDeliverResponse{Error: ErrConflict("Canopy bridge burn identifier is already used")}
	}
	params, err := c.currentProtocolParams()
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	validatorSetID, setErr := c.currentValidatorSetID(params)
	if setErr != nil {
		return &PluginDeliverResponse{Error: setErr}
	}
	if !validAddress(params.CanonicalBridgeAddress) || params.CanonicalChainId == 0 ||
		message.Amount > params.BridgeTransferLimit {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("bridge is disabled or transfer exceeds governed limits")}
	}
	account := new(Account)
	if found, readErr := c.read(KeyForAccount(message.OwnerAddress), account); readErr != nil {
		return &PluginDeliverResponse{Error: readErr}
	} else if !found || account.Amount < message.Amount {
		return &PluginDeliverResponse{Error: ErrInsufficientFunds()}
	}
	state := new(BridgeState)
	_, stateErr := c.read(KeyForBridgeState(), state)
	if stateErr != nil {
		return &PluginDeliverResponse{Error: stateErr}
	}
	if state.OutboundNonce == ^uint64(0) {
		return &PluginDeliverResponse{Error: ErrState("bridge outbound nonce exhausted")}
	}
	state.OutboundNonce++
	account.Amount -= message.Amount
	digest := bridgeReleaseDigest(params, validatorSetID, state.OutboundNonce, message.CanonicalChainRecipient, message.Amount, message.BurnId)
	burn := &BridgeBurn{
		BurnId: append([]byte(nil), message.BurnId...), Nonce: state.OutboundNonce,
		OwnerAddress: append([]byte(nil), message.OwnerAddress...), CanonicalChainRecipient: append([]byte(nil), message.CanonicalChainRecipient...),
		Amount: message.Amount, BurnedHeight: height, ValidatorSetId: validatorSetID,
		CanonicalChainDigest: digest, Status: "pending_release",
	}
	return &PluginDeliverResponse{Error: c.write(map[string]proto.Message{
		string(KeyForAccount(message.OwnerAddress)):     account,
		string(KeyForBridgeState()):                     state,
		string(KeyForBridgeBurn(message.BurnId)):        burn,
		string(KeyForPendingBridgeBurn(message.BurnId)): &ReplayMarker{Id: append([]byte(nil), message.BurnId...)},
	})}
}

func (c *Contract) deliverObserveBridgeRelease(height uint64, message *MessageObserveBridgeRelease) *PluginDeliverResponse {
	burn := new(BridgeBurn)
	if found, err := c.read(KeyForBridgeBurn(message.BurnId), burn); err != nil {
		return &PluginDeliverResponse{Error: err}
	} else if !found || burn.Status != "pending_release" {
		return &PluginDeliverResponse{Error: ErrConflict("bridge burn is not pending release")}
	}
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginDeliverResponse{Error: paramsErr}
	}
	currentSetID, setErr := c.currentValidatorSetID(params)
	if setErr != nil {
		return &PluginDeliverResponse{Error: setErr}
	}
	if burn.Nonce != message.Nonce || burn.Amount != message.Amount || currentSetID != message.ValidatorSetId ||
		!bytes.Equal(burn.CanonicalChainRecipient, message.CanonicalChainRecipient) {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("Base bridge release does not match the committed burn")}
	}
	subject := hashFields(
		[]byte("takusen:bridge-release"), message.BurnId, message.CanonicalChainTxHash, uint64Bytes(message.Nonce),
		message.CanonicalChainRecipient, uint64Bytes(message.Amount), uint64Bytes(message.ValidatorSetId),
	)
	claim := hashFields([]byte("bridge-release"), message.BurnId)
	observation, reached, err := c.observe(observationBridgeRelease, subject, claim, message.ObserverAddress, height)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	records := observationRecords(observationBridgeRelease, subject, claim, message.ObserverAddress, observation)
	if reached {
		burn.Status = "released"
		burn.ReleaseValidatorSetId = message.ValidatorSetId
		burn.CanonicalChainReleaseTxHash = append([]byte(nil), message.CanonicalChainTxHash...)
		records[string(KeyForBridgeBurn(message.BurnId))] = burn
		return &PluginDeliverResponse{Error: c.writeChanges(records, [][]byte{KeyForPendingBridgeBurn(message.BurnId)})}
	}
	return &PluginDeliverResponse{Error: c.write(records)}
}

func bridgeReleaseDigest(params *ProtocolParams, validatorSetID, nonce uint64, recipient []byte, amount uint64, burnID []byte) []byte {
	typeHash := keccak256([]byte(bridgeReleaseType))
	encoded := make([]byte, 0, 32*8)
	encoded = append(encoded, typeHash...)
	encoded = append(encoded, abiUint64(params.CanonicalChainId)...)
	encoded = append(encoded, abiAddress(params.CanonicalBridgeAddress)...)
	encoded = append(encoded, abiUint64(validatorSetID)...)
	encoded = append(encoded, abiUint64(nonce)...)
	encoded = append(encoded, abiAddress(recipient)...)
	encoded = append(encoded, abiUint64(amount)...)
	encoded = append(encoded, burnID...)
	return keccak256(encoded)
}

func keccak256(value []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	_, _ = h.Write(value)
	return h.Sum(nil)
}

func abiUint64(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}

func abiAddress(value []byte) []byte {
	word := make([]byte, 32)
	copy(word[32-len(value):], value)
	return word
}
