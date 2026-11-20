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
	MessageRegisterServicerName      = "takusenRegisterServicer"
	MessageManageServicerName        = "takusenManageServicer"
	MessageObserveDepositName        = "takusenObserveDeposit"
	MessageResolveDepositName        = "takusenResolveDeposit"
	MessageResolveSettlementName     = "takusenResolveSettlement"
	MessageObserveAuthorizationsName = "takusenObserveAuthorizations"
	MessageQueueAuthorizationName    = "takusenQueueAuthorization"
	MessageSubmitExecutionsName      = "takusenSubmitExecutions"
	MessageFinalizeRequestsName      = "takusenFinalizeRequests"
	MessageGovernanceVoteName        = "takusenGovernanceVote"
	MessageObserveBridgeLockName     = "takusenObserveBridgeLock"
	MessageObserveBridgeReleaseName  = "takusenObserveBridgeRelease"
	MessageObserveEpochMintName      = "takusenObserveEpochMint"
	MessageBurnBridgeName            = "takusenBurnBridge"
	MessageSetProducerPayoutName     = "takusenSetProducerPayout"
)

var ContractConfig = &PluginConfig{
	Name:                      "takusen",
	Id:                        22,
	Version:                   5,
	ValidatorSetEpochs:        true,
	GovernanceParameterSpaces: []string{"takusen"},
	SupportedTransactions: []string{
		MessageRegisterServicerName,
		MessageManageServicerName,
		MessageObserveDepositName,
		MessageResolveDepositName,
		MessageResolveSettlementName,
		MessageObserveAuthorizationsName,
		MessageQueueAuthorizationName,
		MessageSubmitExecutionsName,
		MessageFinalizeRequestsName,
		MessageGovernanceVoteName,
		MessageObserveBridgeLockName,
		MessageObserveBridgeReleaseName,
		MessageObserveEpochMintName,
		MessageBurnBridgeName,
		MessageSetProducerPayoutName,
	},
	TransactionTypeUrls: []string{
		"type.googleapis.com/types.MessageRegisterServicer",
		"type.googleapis.com/types.MessageManageServicer",
		"type.googleapis.com/types.MessageObserveDeposit",
		"type.googleapis.com/types.MessageResolveDeposit",
		"type.googleapis.com/types.MessageResolveSettlement",
		"type.googleapis.com/types.MessageObserveAuthorizations",
		"type.googleapis.com/types.MessageQueueAuthorization",
		"type.googleapis.com/types.MessageSubmitExecutions",
		"type.googleapis.com/types.MessageFinalizeRequests",
		"type.googleapis.com/types.MessageGovernanceVote",
		"type.googleapis.com/types.MessageObserveBridgeLock",
		"type.googleapis.com/types.MessageObserveBridgeRelease",
		"type.googleapis.com/types.MessageObserveEpochMint",
		"type.googleapis.com/types.MessageBurnBridge",
		"type.googleapis.com/types.MessageSetProducerPayout",
	},
	CustomStatePrefixes: [][]byte{
		enclavePrefix, servicerPrefix, requestPrefix, executionPrefix,
		observationPrefix, blockAnchorPrefix,
		quorumProofPrefix, quorumSharePrefix,
		depositPrefix, creditPrefix, reservationPrefix,
		observationClaimPrefix, protocolParamsPrefix,
		slashEvidencePrefix, producerPayoutPrefix,
		producerPrefix, epochAuthorizationPrefix, bridgeStatePrefix,
		bridgeMintPrefix, bridgeNoncePrefix, bridgeBurnPrefix, epochClockPrefix,
		assignmentIndexPrefix, epochValidatorPrefix, settlementIndexPrefix, producerIdentityPrefix,
		rotationProofIndexPrefix, latestEpochPrefix, provisionalReservationIndexPrefix,
		activeServicerIndexPrefix, pendingEpochAuthorizationPrefix, pendingBridgeBurnPrefix,
		handoffManifestPrefix, domainRotationStatePrefix,
		consensusCertificatePrefix, nativeAuthorizationIntentPrefix, pendingAuthorizationPrefix,
		timeoutCandidateCursorPrefix, uncertifiedSettlementIndexPrefix, certifiedSettlementIndexPrefix,
		settlementCandidateCursorPrefix,
		pendingEpochAccountingPrefix,
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
	certificateRecords, certificateDeletes := c.consumeAuxiliaryCertificates(request.Height, request.AuxiliaryCertificates)
	for key, record := range certificateRecords {
		records[key] = record
	}
	deletes = append(deletes, certificateDeletes...)
	if timeoutErr := c.stageTimedOutRequests(request.Height, records, &deletes); timeoutErr != nil {
		return &PluginBeginResponse{Error: timeoutErr}
	}
	if cursorErr := c.advanceSettlementCandidateCursor(records); cursorErr != nil {
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
	case *MessageRegisterServicer:
		signer, err = checkRegisterServicer(message)
	case *MessageManageServicer:
		signer, err = checkManageServicer(message)
	case *MessageObserveDeposit:
		signer, err = checkObserveDeposit(message)
	case *MessageResolveDeposit:
		signer, err = checkResolveDeposit(message)
	case *MessageResolveSettlement:
		signer, err = checkResolveSettlement(message)
	case *MessageObserveAuthorizations:
		signer, err = checkObserveAuthorizations(message)
	case *MessageQueueAuthorization:
		signer, err = checkQueueAuthorization(message)
	case *MessageSubmitExecutions:
		signer, err = checkSubmitExecutions(message)
	case *MessageFinalizeRequests:
		signer, err = checkFinalizeRequests(message)
	case *MessageGovernanceVote:
		signer, err = checkGovernanceVote(message)
	case *MessageObserveBridgeLock:
		signer, err = checkObserveBridgeLock(message)
	case *MessageObserveBridgeRelease:
		signer, err = checkObserveBridgeRelease(message)
	case *MessageObserveEpochMint:
		signer, err = checkObserveEpochMint(message)
	case *MessageBurnBridge:
		signer, err = checkBurnBridge(message)
	case *MessageSetProducerPayout:
		signer, err = checkSetProducerPayout(message)
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
	case *MessageRegisterServicer:
		return c.deliverRegisterServicer(request.Height, request.TimeMicros, message)
	case *MessageManageServicer:
		return c.deliverManageServicer(request.Height, request.TimeMicros, message)
	case *MessageObserveDeposit:
		return c.deliverObserveDeposit(request.Height, message)
	case *MessageResolveDeposit:
		return c.deliverResolveDeposit(request.Height, message)
	case *MessageResolveSettlement:
		return c.deliverResolveSettlement(request.Height, message)
	case *MessageObserveAuthorizations:
		return c.deliverObserveAuthorizations(request.Height, message)
	case *MessageQueueAuthorization:
		return c.deliverQueueAuthorization(request.Height, message)
	case *MessageSubmitExecutions:
		return c.deliverSubmitExecutions(request.Height, message)
	case *MessageFinalizeRequests:
		return c.deliverFinalizeRequests(request.Height, message)
	case *MessageGovernanceVote:
		return c.deliverGovernanceVote(request.Height, message)
	case *MessageObserveBridgeLock:
		return c.deliverObserveBridgeLock(request.Height, message)
	case *MessageObserveBridgeRelease:
		return c.deliverObserveBridgeRelease(request.Height, message)
	case *MessageObserveEpochMint:
		return c.deliverObserveEpochMint(request.Height, message)
	case *MessageBurnBridge:
		return c.deliverBurnBridge(request.Height, message)
	case *MessageSetProducerPayout:
		return c.deliverSetProducerPayout(message)
	default:
		return &PluginDeliverResponse{Error: ErrInvalidMessageCast()}
	}
}
