package contract

import (
	"encoding/json"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	MessageObserveEnclaveName        = "takusenObserveEnclave"
	MessageRevokeEnclaveName         = "takusenRevokeEnclave"
	MessageRegisterServicerName      = "takusenRegisterServicer"
	MessageUpdateServicerName        = "takusenUpdateServicer"
	MessageObserveDepositName        = "takusenObserveDeposit"
	MessageResolveDepositName        = "takusenResolveDeposit"
	MessageResolveSettlementName     = "takusenResolveSettlement"
	MessageObserveAuthorizationName  = "takusenObserveAuthorization"
	MessageObserveAuthorizationsName = "takusenObserveAuthorizations"
	MessageQueueAuthorizationName    = "takusenQueueAuthorization"
	MessageSubmitExecutionName       = "takusenSubmitExecution"
	MessageSubmitExecutionsName      = "takusenSubmitExecutions"
	MessageReassignRequestName       = "takusenReassignRequest"
	MessageFinalizeRequestName       = "takusenFinalizeRequest"
	MessageFinalizeRequestsName      = "takusenFinalizeRequests"
	MessageSubmitQuorumSignatureName = "takusenSubmitQuorumSignature"
	MessageObserveBridgeLockName     = "takusenObserveBridgeLock"
	MessageObserveBridgeReleaseName  = "takusenObserveBridgeRelease"
	MessageObserveEpochMintName      = "takusenObserveEpochMint"
	MessageBurnBridgeName            = "takusenBurnBridge"
	MessageQueueServicerStakeName    = "takusenQueueServicerStake"
	MessageWithdrawUnbondedName      = "takusenWithdrawUnbonded"
	MessageSetProducerPayoutName     = "takusenSetProducerPayout"
	MessageObserveSlashEvidenceName  = "takusenObserveSlashEvidence"
)

var ContractConfig = &PluginConfig{
	Name:                      "takusen",
	Id:                        22,
	Version:                   1,
	ValidatorSetEpochs:        true,
	GovernanceParameterSpaces: []string{"takusen"},
	SupportedTransactions: []string{
		MessageObserveEnclaveName,
		MessageRevokeEnclaveName,
		MessageRegisterServicerName,
		MessageUpdateServicerName,
		MessageObserveDepositName,
		MessageResolveDepositName,
		MessageResolveSettlementName,
		MessageObserveAuthorizationName,
		MessageObserveAuthorizationsName,
		MessageQueueAuthorizationName,
		MessageSubmitExecutionName,
		MessageSubmitExecutionsName,
		MessageReassignRequestName,
		MessageFinalizeRequestName,
		MessageFinalizeRequestsName,
		MessageSubmitQuorumSignatureName,
		MessageObserveBridgeLockName,
		MessageObserveBridgeReleaseName,
		MessageObserveEpochMintName,
		MessageBurnBridgeName,
		MessageQueueServicerStakeName,
		MessageWithdrawUnbondedName,
		MessageSetProducerPayoutName,
		MessageObserveSlashEvidenceName,
	},
	TransactionTypeUrls: []string{
		"type.googleapis.com/types.MessageObserveEnclave",
		"type.googleapis.com/types.MessageRevokeEnclave",
		"type.googleapis.com/types.MessageRegisterServicer",
		"type.googleapis.com/types.MessageUpdateServicer",
		"type.googleapis.com/types.MessageObserveDeposit",
		"type.googleapis.com/types.MessageResolveDeposit",
		"type.googleapis.com/types.MessageResolveSettlement",
		"type.googleapis.com/types.MessageObserveAuthorization",
		"type.googleapis.com/types.MessageObserveAuthorizations",
		"type.googleapis.com/types.MessageQueueAuthorization",
		"type.googleapis.com/types.MessageSubmitExecution",
		"type.googleapis.com/types.MessageSubmitExecutions",
		"type.googleapis.com/types.MessageReassignRequest",
		"type.googleapis.com/types.MessageFinalizeRequest",
		"type.googleapis.com/types.MessageFinalizeRequests",
		"type.googleapis.com/types.MessageSubmitQuorumSignature",
		"type.googleapis.com/types.MessageObserveBridgeLock",
		"type.googleapis.com/types.MessageObserveBridgeRelease",
		"type.googleapis.com/types.MessageObserveEpochMint",
		"type.googleapis.com/types.MessageBurnBridge",
		"type.googleapis.com/types.MessageQueueServicerStake",
		"type.googleapis.com/types.MessageWithdrawUnbonded",
		"type.googleapis.com/types.MessageSetProducerPayout",
		"type.googleapis.com/types.MessageObserveSlashEvidence",
	},
	CustomStatePrefixes: [][]byte{
		enclavePrefix, servicerPrefix, requestPrefix, executionPrefix,
		observationPrefix, blockAnchorPrefix,
		quorumProofPrefix, quorumSharePrefix,
		depositPrefix, creditPrefix, reservationPrefix,
		observationClaimPrefix, protocolParamsPrefix, stakeChangePrefix,
		unbondingPrefix, slashEvidencePrefix, producerPayoutPrefix,
		producerPrefix, epochAuthorizationPrefix, bridgeStatePrefix,
		bridgeMintPrefix, bridgeNoncePrefix, bridgeBurnPrefix, epochClockPrefix,
		assignmentIndexPrefix, epochValidatorPrefix, settlementIndexPrefix, producerIdentityPrefix,
		rotationProofIndexPrefix, pendingSlashPrefix, latestEpochPrefix, provisionalReservationIndexPrefix,
		activeServicerIndexPrefix, pendingEpochAuthorizationPrefix, pendingBridgeBurnPrefix,
		handoffManifestPrefix, domainRotationStatePrefix, handoffCancellationManifestPrefix,
		consensusCertificatePrefix, nativeAuthorizationIntentPrefix, pendingAuthorizationPrefix,
	},
}

func init() {
	file_account_proto_init()
	file_event_proto_init()
	file_plugin_proto_init()
	file_tx_proto_init()
	for _, file := range []protoreflect.FileDescriptor{
		anypb.File_google_protobuf_any_proto,
		File_account_proto, File_event_proto, File_plugin_proto, File_tx_proto,
	} {
		fd, _ := proto.Marshal(protodesc.ToFileDescriptorProto(file))
		ContractConfig.FileDescriptorProtos = append(ContractConfig.FileDescriptorProtos, fd)
	}
}

type Contract struct {
	Config    Config
	FSMConfig *PluginFSMConfig
	plugin    stateStore
	fsmId     uint64
}

type stateStore interface {
	StateRead(*Contract, *PluginStateReadRequest) (*PluginStateReadResponse, *PluginError)
	StateWrite(*Contract, *PluginStateWriteRequest) (*PluginStateWriteResponse, *PluginError)
}

func (c *Contract) Genesis(request *PluginGenesisRequest) *PluginGenesisResponse {
	if request == nil || len(request.GenesisJson) == 0 {
		return &PluginGenesisResponse{Error: ErrState("plugin genesis document is unavailable")}
	}
	var genesis struct {
		PluginGenesis map[string]json.RawMessage `json:"pluginGenesis"`
	}
	if err := json.Unmarshal(request.GenesisJson, &genesis); err != nil {
		return &PluginGenesisResponse{Error: ErrInvalidTransaction("invalid plugin genesis document")}
	}
	raw, ok := genesis.PluginGenesis[ContractConfig.Name]
	if !ok || len(raw) == 0 {
		return &PluginGenesisResponse{Error: ErrInvalidTransaction("Takusen protocol parameters are missing from genesis")}
	}
	params := new(ProtocolParams)
	if err := (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(raw, params); err != nil {
		return &PluginGenesisResponse{Error: ErrInvalidTransaction("invalid Takusen genesis parameters")}
	}
	if params.Revision != 1 {
		return &PluginGenesisResponse{Error: ErrInvalidTransaction("Takusen genesis parameters must start at revision 1")}
	}
	if err := validateProtocolParams(params); err != nil {
		return &PluginGenesisResponse{Error: err}
	}
	if err := c.write(map[string]proto.Message{string(KeyForProtocolParams()): params}); err != nil {
		return &PluginGenesisResponse{Error: err}
	}
	return &PluginGenesisResponse{}
}

func (c *Contract) BeginBlock(request *PluginBeginRequest) *PluginBeginResponse {
	if request == nil || request.Height == 0 {
		return &PluginBeginResponse{Error: ErrState("begin block is missing a height")}
	}
	anchor := &BlockAnchor{Height: request.Height, PreviousBlockHash: request.PreviousBlockHash}
	encoded, err := Marshal(anchor)
	if err != nil {
		return &PluginBeginResponse{Error: err}
	}
	params, paramsErr := c.currentProtocolParams()
	if paramsErr != nil {
		return &PluginBeginResponse{Error: paramsErr}
	}
	clock, clockErr := c.currentEpochClock(params)
	if clockErr != nil {
		return &PluginBeginResponse{Error: clockErr}
	}
	records, deletes, snapshotErr := c.reconcileEpochValidatorSnapshot(clock.CurrentEpoch, request.ValidatorSet)
	if snapshotErr != nil {
		return &PluginBeginResponse{Error: snapshotErr}
	}
	if len(request.NextValidatorSet) != 0 {
		if clock.CurrentEpoch == ^uint64(0) {
			return &PluginBeginResponse{Error: ErrState("epoch counter overflow")}
		}
		nextRecords, nextDeletes, nextErr := c.reconcileEpochValidatorSnapshot(clock.CurrentEpoch+1, request.NextValidatorSet)
		if nextErr != nil {
			return &PluginBeginResponse{Error: nextErr}
		}
		for key, value := range nextRecords {
			records[key] = value
		}
		deletes = append(deletes, nextDeletes...)
	}
	for key, record := range c.consumeAuxiliaryCertificates(request.Height, request.AuxiliaryCertificates, request.AuxiliaryValidatorSet) {
		records[key] = record
	}
	if cursorErr := c.advanceTimeoutCandidateCursor(records); cursorErr != nil {
		return &PluginBeginResponse{Error: cursorErr}
	}
	if expired, pruneErr := c.expiredPendingAuthorizations(request.Height, 32); pruneErr == nil {
		deletes = append(deletes, expired...)
	}
	write := &PluginStateWriteRequest{Sets: []*PluginSetOp{{Key: KeyForBlockAnchor(), Value: encoded}}}
	for _, key := range sortedRecordKeys(records) {
		value, marshalErr := Marshal(records[key])
		if marshalErr != nil {
			return &PluginBeginResponse{Error: marshalErr}
		}
		write.Sets = append(write.Sets, &PluginSetOp{Key: []byte(key), Value: value})
	}
	for _, key := range deletes {
		write.Deletes = append(write.Deletes, &PluginDeleteOp{Key: key})
	}
	response, err := c.plugin.StateWrite(c, write)
	if err != nil {
		return &PluginBeginResponse{Error: err}
	}
	return &PluginBeginResponse{Error: response.Error}
}

func (c *Contract) EndBlock(request *PluginEndRequest) *PluginEndResponse {
	return c.endBlock(request)
}

func (c *Contract) CheckTx(request *PluginCheckRequest) *PluginCheckResponse {
	if request.Tx == nil || request.Tx.Fee == 0 {
		return &PluginCheckResponse{Error: ErrInvalidTransaction("Takusen transactions require a positive native fee")}
	}
	message, err := FromAny(request.Tx.Msg)
	if err != nil {
		return &PluginCheckResponse{Error: err}
	}
	var signer []byte
	switch message := message.(type) {
	case *MessageObserveEnclave:
		signer, err = checkObserveEnclave(message)
	case *MessageRevokeEnclave:
		signer, err = checkRevokeEnclave(message)
	case *MessageRegisterServicer:
		signer, err = checkRegisterServicer(message)
	case *MessageUpdateServicer:
		signer, err = checkUpdateServicer(message)
	case *MessageObserveDeposit:
		signer, err = checkObserveDeposit(message)
	case *MessageResolveDeposit:
		signer, err = checkResolveDeposit(message)
	case *MessageResolveSettlement:
		signer, err = checkResolveSettlement(message)
	case *MessageObserveAuthorization:
		signer, err = checkObserveAuthorization(message)
	case *MessageObserveAuthorizations:
		signer, err = checkObserveAuthorizations(message)
	case *MessageQueueAuthorization:
		signer, err = checkQueueAuthorization(message)
	case *MessageSubmitExecution:
		signer, err = checkSubmitExecution(message)
	case *MessageSubmitExecutions:
		signer, err = checkSubmitExecutions(message)
	case *MessageReassignRequest:
		signer, err = checkReassignRequest(message)
	case *MessageFinalizeRequest:
		signer, err = checkFinalizeRequest(message)
	case *MessageFinalizeRequests:
		signer, err = checkFinalizeRequests(message)
	case *MessageSubmitQuorumSignature:
		signer, err = checkSubmitQuorumSignature(message)
	case *MessageObserveBridgeLock:
		signer, err = checkObserveBridgeLock(message)
	case *MessageObserveBridgeRelease:
		signer, err = checkObserveBridgeRelease(message)
	case *MessageObserveEpochMint:
		signer, err = checkObserveEpochMint(message)
	case *MessageBurnBridge:
		signer, err = checkBurnBridge(message)
	case *MessageQueueServicerStake:
		signer, err = checkQueueServicerStake(message)
	case *MessageWithdrawUnbonded:
		signer, err = checkWithdrawUnbonded(message)
	case *MessageSetProducerPayout:
		signer, err = checkSetProducerPayout(message)
	case *MessageObserveSlashEvidence:
		signer, err = checkObserveSlashEvidence(message)
	default:
		return &PluginCheckResponse{Error: ErrInvalidMessageCast()}
	}
	if err != nil {
		return &PluginCheckResponse{Error: err}
	}
	return &PluginCheckResponse{AuthorizedSigners: [][]byte{signer}}
}

func (c *Contract) DeliverTx(request *PluginDeliverRequest) *PluginDeliverResponse {
	if request == nil {
		return &PluginDeliverResponse{Error: ErrInvalidTransaction("missing plugin delivery request")}
	}
	if request.Tx == nil {
		return c.deliverGovernedParameter(request.GovernanceParameterSpace, request.GovernanceParameterKey, request.GovernanceParameterValue)
	}
	message, err := FromAny(request.Tx.Msg)
	if err != nil {
		return &PluginDeliverResponse{Error: err}
	}
	switch message := message.(type) {
	case *MessageObserveEnclave:
		return c.deliverObserveEnclave(request.Height, message)
	case *MessageRevokeEnclave:
		return c.deliverRevokeEnclave(request.Height, message)
	case *MessageRegisterServicer:
		return c.deliverRegisterServicer(request.Height, message)
	case *MessageUpdateServicer:
		return c.deliverUpdateServicer(message)
	case *MessageObserveDeposit:
		return c.deliverObserveDeposit(request.Height, message)
	case *MessageResolveDeposit:
		return c.deliverResolveDeposit(request.Height, message)
	case *MessageResolveSettlement:
		return c.deliverResolveSettlement(request.Height, message)
	case *MessageObserveAuthorization:
		return c.deliverObserveAuthorization(request.Height, message)
	case *MessageObserveAuthorizations:
		return c.deliverObserveAuthorizations(request.Height, message)
	case *MessageQueueAuthorization:
		return c.deliverQueueAuthorization(request.Height, message)
	case *MessageSubmitExecution:
		return c.deliverSubmitExecution(request.Height, message)
	case *MessageSubmitExecutions:
		return c.deliverSubmitExecutions(request.Height, message)
	case *MessageReassignRequest:
		return c.deliverReassignRequest(request.Height, message)
	case *MessageFinalizeRequest:
		return c.deliverFinalizeRequest(request.Height, message)
	case *MessageFinalizeRequests:
		return c.deliverFinalizeRequests(request.Height, message)
	case *MessageSubmitQuorumSignature:
		return c.deliverSubmitQuorumSignature(request.Height, message)
	case *MessageObserveBridgeLock:
		return c.deliverObserveBridgeLock(request.Height, message)
	case *MessageObserveBridgeRelease:
		return c.deliverObserveBridgeRelease(request.Height, message)
	case *MessageObserveEpochMint:
		return c.deliverObserveEpochMint(request.Height, message)
	case *MessageBurnBridge:
		return c.deliverBurnBridge(request.Height, message)
	case *MessageQueueServicerStake:
		return c.deliverQueueServicerStake(request.Height, message)
	case *MessageWithdrawUnbonded:
		return c.deliverWithdrawUnbonded(request.Height, message)
	case *MessageSetProducerPayout:
		return c.deliverSetProducerPayout(message)
	case *MessageObserveSlashEvidence:
		return c.deliverObserveSlashEvidence(request.Height, message)
	default:
		return &PluginDeliverResponse{Error: ErrInvalidMessageCast()}
	}
}
