package contract

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	drandbls "github.com/drand/kyber-bls12381"
	"google.golang.org/protobuf/proto"
)

func testBDNPublicKey(value int64) []byte {
	suite := drandbls.NewBLS12381Suite()
	encoded, err := suite.G1().Point().Mul(suite.G1().Scalar().SetInt64(value), nil).MarshalBinary()
	if err != nil {
		panic(err)
	}
	return encoded
}

func seedQueuedRotation(t *testing.T, store *memoryStateStore, params *ProtocolParams, oldSetID uint64) {
	t.Helper()
	clock := new(EpochClock)
	if encoded := store.values[string(KeyForEpochClock())]; len(encoded) == 0 || Unmarshal(encoded, clock) != nil {
		t.Fatal("epoch clock is unavailable")
	}
	if !clock.ValidatorHandoffPrepared || len(clock.ValidatorHandoffDomains) == 0 || clock.ValidatorHandoffAttempt == 0 {
		t.Fatal("validator handoff attempt is unavailable")
	}
	// Keep fixtures short while retaining the attempt-one cutoff invariant.
	clock.ValidatorHandoffTimestamp = clock.ConsensusTimeSeconds
	clock.ValidatorHandoffOutgoingAuthorityCutoff = clock.ValidatorHandoffTimestamp
	store.put(t, KeyForEpochClock(), clock)
	generation := validatorHandoffGeneration(clock)
	for _, domain := range params.SettlementDomains {
		if domain == nil {
			continue
		}
		proofID := hashFields([]byte("scheduled-rotation"), domain.Id, uint64Bytes(oldSetID))
		store.put(t, KeyForQuorumProof(proofID), &QuorumProof{
			ProofKind: "validator-set-rotation-queued", ProofId: proofID, ValidatorSetId: oldSetID,
			NewValidatorSetId: oldSetID + 1, CompletedHeight: oldSetID * 10, SettlementDomainId: domain.Id,
			HandoffGeneration: generation, HandoffTimestamp: clock.ValidatorHandoffTimestamp,
		})
		store.put(t, KeyForQueuedRotationIndex(domain.Id, oldSetID, oldSetID+1), &ReplayMarker{Id: proofID})
	}
}

func epochEndRequest(height uint64, proposer []byte) *PluginEndRequest {
	return epochEndRequestWithWeights(height, height, proposer, 100+height, 100+height)
}

func epochEndRequestAt(height, unixSeconds uint64, proposer []byte) *PluginEndRequest {
	return epochEndRequestWithWeights(height, unixSeconds, proposer, 100+height, 100+height)
}

func epochEndRequestWithWeights(height, unixSeconds uint64, proposer []byte, weights ...uint64) *PluginEndRequest {
	var encoded bytes.Buffer
	encoded.WriteByte(activeValidatorSetEncodingVersion)
	_ = binary.Write(&encoded, binary.BigEndian, uint64(1))
	_ = binary.Write(&encoded, binary.BigEndian, uint32(len(weights)))
	for index, weight := range weights {
		address := bytes.Repeat([]byte{byte(index + 1)}, addressSize)
		publicKey := testBDNPublicKey(int64(index + 1))
		encoded.Write(address)
		_ = binary.Write(&encoded, binary.BigEndian, uint16(len(publicKey)))
		encoded.Write(publicKey)
		_ = binary.Write(&encoded, binary.BigEndian, weight)
		_ = binary.Write(&encoded, binary.BigEndian, uint16(0))
	}
	return &PluginEndRequest{Height: height, ProposerAddress: proposer, TimeMicros: unixSeconds * 1_000_000, NextValidatorSet: encoded.Bytes()}
}

func completePreparedClock(clock *EpochClock, params *ProtocolParams, rosterHash []byte) {
	clock.ValidatorHandoffPrepared = true
	clock.ValidatorHandoffDomains = authorityHandoffDomains(params)
	clock.ValidatorHandoffDomainSetHash = validatorHandoffDomainSetHash(clock.ValidatorHandoffDomains)
	clock.ValidatorHandoffRosterHash = append([]byte(nil), rosterHash...)
	if len(clock.ValidatorHandoffRosterHash) == 0 {
		clock.ValidatorHandoffRosterHash = bytes.Repeat([]byte{0x51}, 32)
	}
	clock.ValidatorHandoffAttempt = 1
	clock.ValidatorHandoffNativeChainId = 1
	clock.ValidatorHandoffNoticeSeconds = params.ValidatorHandoffNoticeSeconds
	clock.ValidatorHandoffOutgoingAuthorityCutoff = clock.ValidatorHandoffTimestamp
}

type memoryStateStore struct{ values map[string][]byte }

func newMemoryContract(t *testing.T) (*Contract, *memoryStateStore, []byte, []byte) {
	t.Helper()
	store := &memoryStateStore{values: make(map[string][]byte)}
	contract := &Contract{Config: Config{ChainId: 1}, plugin: store}
	first, second := bytes.Repeat([]byte{1}, 20), bytes.Repeat([]byte{2}, 20)
	firstValidator := &Validator{Address: first, PublicKey: testBDNPublicKey(1), StakedAmount: 100, Committees: []uint64{1}}
	secondValidator := &Validator{Address: second, PublicKey: testBDNPublicKey(2), StakedAmount: 100, Committees: []uint64{1}}
	store.put(t, KeyForValidator(first), firstValidator)
	store.put(t, KeyForValidator(second), secondValidator)
	store.put(t, KeyForEpochValidator(1, first), firstValidator)
	store.put(t, KeyForEpochValidator(1, second), secondValidator)
	return contract, store, first, second
}

func (s *memoryStateStore) put(t *testing.T, key []byte, value any) {
	t.Helper()
	encoded, err := Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	s.values[string(key)] = encoded
	if servicer, ok := value.(*Servicer); ok && servicer.Active {
		marker, marshalErr := Marshal(&ReplayMarker{Id: append([]byte(nil), servicer.OwnerAddress...)})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		s.values[string(KeyForActiveServicer(servicer.OwnerAddress))] = marker
	}
}

func (s *memoryStateStore) StateRead(_ *Contract, request *PluginStateReadRequest) (*PluginStateReadResponse, *PluginError) {
	response := new(PluginStateReadResponse)
	for _, key := range request.Keys {
		result := &PluginReadResult{QueryId: key.QueryId}
		if value, ok := s.values[string(key.Key)]; ok {
			result.Entries = append(result.Entries, &PluginStateEntry{Key: append([]byte(nil), key.Key...), Value: append([]byte(nil), value...)})
		}
		response.Results = append(response.Results, result)
	}
	for _, query := range request.Ranges {
		result := &PluginReadResult{QueryId: query.QueryId}
		keys := make([]string, 0)
		for key := range s.values {
			if bytes.HasPrefix([]byte(key), query.Prefix) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		if query.Reverse {
			slices.Reverse(keys)
		}
		for _, key := range keys {
			if len(query.StartAfter) != 0 {
				comparison := bytes.Compare([]byte(key), query.StartAfter)
				if (!query.Reverse && comparison <= 0) || (query.Reverse && comparison >= 0) {
					continue
				}
			}
			if query.Limit != 0 && uint64(len(result.Entries)) >= query.Limit {
				break
			}
			result.Entries = append(result.Entries, &PluginStateEntry{Key: []byte(key), Value: append([]byte(nil), s.values[key]...)})
		}
		response.Results = append(response.Results, result)
	}
	return response, nil
}

func TestConsensusRangeReadPaginatesPastFiveThousandEntries(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	prefix := JoinLenPrefix([]byte{200})
	for index := range 5_001 {
		key := append(append([]byte(nil), prefix...), JoinLenPrefix(uint64Bytes(uint64(index)))...)
		store.values[string(key)] = []byte{1}
	}
	entries, err := contract.rangeRead(prefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5_001 {
		t.Fatalf("paginated range returned %d entries", len(entries))
	}
	for index := 1; index < len(entries); index++ {
		if bytes.Compare(entries[index-1].Key, entries[index].Key) >= 0 {
			t.Fatal("paginated range was duplicated or reordered")
		}
	}
}

func (s *memoryStateStore) StateWrite(_ *Contract, request *PluginStateWriteRequest) (*PluginStateWriteResponse, *PluginError) {
	for _, set := range request.Sets {
		s.values[string(set.Key)] = append([]byte(nil), set.Value...)
	}
	for _, deletion := range request.Deletes {
		delete(s.values, string(deletion.Key))
	}
	return new(PluginStateWriteResponse), nil
}

func TestServicerCanRestoreSlashedBondOnKeyRotation(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	owner := bytes.Repeat([]byte{7}, 20)
	teeKeyID := "ed25519:replacement"
	params := defaultProtocolParams()
	params.MinimumServicerBond = 100_000
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEnclave(teeKeyID), &EnclaveKey{OwnerAddress: owner, TeeKeyId: teeKeyID, Active: true})
	store.put(t, KeyForAccount(owner), &Account{Address: owner, Amount: 1_000})
	payouts := testPayouts(params, owner)
	store.put(t, KeyForServicer(owner), &Servicer{OwnerAddress: owner, Payouts: payouts, TeeKeyId: "old", Models: []string{"model"}, Bond: 99_000})

	response := contract.deliverUpdateServicer(&MessageUpdateServicer{
		OwnerAddress: owner, Payouts: payouts, TeeKeyId: teeKeyID,
		Models: []string{"model"}, AdditionalBond: 1_000, Active: true,
	})
	if response.Error != nil {
		t.Fatal(response.Error)
	}
	servicer := new(Servicer)
	if err := Unmarshal(store.values[string(KeyForServicer(owner))], servicer); err != nil {
		t.Fatal(err)
	}
	account := new(Account)
	if err := Unmarshal(store.values[string(KeyForAccount(owner))], account); err != nil {
		t.Fatal(err)
	}
	if servicer.Bond != 100_000 || !servicer.Active || servicer.TeeKeyId != teeKeyID || account.Amount != 0 {
		t.Fatalf("unexpected top-up state: servicer=%+v account=%+v", servicer, account)
	}
}

func TestActiveServicerIndexTracksRegistrationAndDeactivation(t *testing.T) {
	contract, store, owner, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForAccount(owner), &Account{Address: owner, Amount: params.MinimumServicerBond})
	store.put(t, KeyForEnclave("key"), &EnclaveKey{OwnerAddress: owner, TeeKeyId: "key", Active: true})
	register := &MessageRegisterServicer{
		OwnerAddress: owner, Payouts: testPayouts(params, owner), TeeKeyId: "key", Models: []string{"model"}, Bond: params.MinimumServicerBond,
	}
	if response := contract.deliverRegisterServicer(1, register); response.Error != nil {
		t.Fatal(response.Error)
	}
	if found, err := contract.read(KeyForActiveServicer(owner), new(ReplayMarker)); err != nil || !found {
		t.Fatalf("active servicer index missing: found=%v err=%v", found, err)
	}
	update := &MessageUpdateServicer{
		OwnerAddress: owner, Payouts: testPayouts(params, owner), TeeKeyId: "key", Models: []string{"model"}, Active: false,
	}
	if response := contract.deliverUpdateServicer(update); response.Error != nil {
		t.Fatal(response.Error)
	}
	if found, err := contract.read(KeyForActiveServicer(owner), new(ReplayMarker)); err != nil || found {
		t.Fatalf("inactive servicer remains indexed: found=%v err=%v", found, err)
	}
}

func testPayouts(params *ProtocolParams, address []byte) []*SettlementPayout {
	result := make([]*SettlementPayout, 0, len(params.SettlementDomains))
	for _, domain := range params.SettlementDomains {
		if domain != nil && domain.Active {
			result = append(result, &SettlementPayout{SettlementDomainId: append([]byte(nil), domain.Id...), Address: append([]byte(nil), address...)})
		}
	}
	return result
}

func TestAdversarialObservationsRejectConflictsStaleValidatorsAndReplay(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	txHash := bytes.Repeat([]byte{3}, 32)
	requester := bytes.Repeat([]byte{4}, 20)
	message := &MessageObserveDeposit{ObserverAddress: first, SettlementDomainId: testSettlementDomainID(), ChainTxHash: txHash, Requester: requester, AmountMicros: 100, TokenAmount: []byte{100}}
	if response := contract.deliverObserveDeposit(10, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	conflict := &MessageObserveDeposit{ObserverAddress: first, SettlementDomainId: testSettlementDomainID(), ChainTxHash: txHash, Requester: requester, AmountMicros: 101, TokenAmount: []byte{101}}
	if response := contract.deliverObserveDeposit(11, conflict); response.Error == nil {
		t.Fatal("validator equivocation for one Base deposit was accepted")
	}
	stale := &MessageObserveDeposit{ObserverAddress: bytes.Repeat([]byte{9}, 20), SettlementDomainId: testSettlementDomainID(), ChainTxHash: txHash, Requester: requester, AmountMicros: 100, TokenAmount: []byte{100}}
	if response := contract.deliverObserveDeposit(11, stale); response.Error == nil {
		t.Fatal("non-committee validator observation was accepted")
	}
	message.ObserverAddress = second
	if response := contract.deliverObserveDeposit(12, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if _, ok := store.values[string(KeyForDeposit(testSettlementDomainID(), txHash))]; !ok {
		t.Fatal("quorum deposit was not committed")
	}
	if response := contract.deliverObserveDeposit(13, message); response.Error == nil {
		t.Fatal("committed deposit replay was accepted")
	}
	params := defaultProtocolParams()
	params.Revision = 1
	params.ApprovedPcrs = []*PCRPolicy{testPCRPolicy()}
	encoded, encodeErr := Marshal(params)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatal(response.Error)
	}
	conflictingParams := proto.Clone(params).(*ProtocolParams)
	conflictingParams.EmissionPerEpoch = 1
	encoded, encodeErr = Marshal(conflictingParams)
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error == nil {
		t.Fatal("a second parameter document with the same revision was accepted")
	}
	committed := new(ProtocolParams)
	if found, err := contract.read(KeyForProtocolParams(), committed); err != nil || !found || committed.Revision != 1 {
		t.Fatalf("governed params = %#v, found = %v, err = %v", committed, found, err)
	}
}

func TestEnclaveRegistrationRequiresGovernedEvidenceAndNonzeroPCRs(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	owner := bytes.Repeat([]byte{7}, 20)
	nonce := []byte("registration-nonce")
	userData := bytes.Repeat([]byte{8}, 32)
	keyDigest := sha256.Sum256(publicKey)
	attestationHash := sha256.Sum256([]byte("synthetic-attestation"))
	message := &MessageObserveEnclave{
		ObserverAddress: bytes.Repeat([]byte{9}, 20), OwnerAddress: owner,
		TeeKeyId: "ed25519:" + hex.EncodeToString(keyDigest[:]), PublicKey: publicKey, AttestationHash: attestationHash[:],
		Pcr0: bytes.Repeat([]byte{1}, 48), Pcr1: bytes.Repeat([]byte{2}, 48), Pcr2: bytes.Repeat([]byte{3}, 48),
		Nonce: nonce, UserData: userData,
	}
	registrationDigest := sha256.New()
	_, _ = registrationDigest.Write([]byte("takusen:nitro-registration\x00"))
	_, _ = registrationDigest.Write(message.Nonce)
	_, _ = registrationDigest.Write([]byte{0})
	_, _ = registrationDigest.Write(message.UserData)
	message.ProofSignature = ed25519.Sign(privateKey, registrationDigest.Sum(nil))
	for bank := 0; bank < 3; bank++ {
		candidate := proto.Clone(message).(*MessageObserveEnclave)
		switch bank {
		case 0:
			candidate.Pcr0 = make([]byte, 48)
		case 1:
			candidate.Pcr1 = make([]byte, 48)
		case 2:
			candidate.Pcr2 = make([]byte, 48)
		}
		if _, checkErr := checkObserveEnclave(candidate); checkErr == nil {
			t.Fatalf("registration accepted all-zero PCR bank %d", bank)
		}
	}

	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision = 1
	params.ApprovedPcrs = []*PCRPolicy{testPCRPolicy()}
	store.put(t, KeyForProtocolParams(), params)
	if response := contract.deliverObserveEnclave(10, message); response.Error == nil {
		t.Fatal("governed Nitro mode accepted an empty attestation document")
	}
}

func TestObservationVotesCannotCrossValidatorEpochsOrRepriceStake(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 1
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEpochClock(), &EpochClock{CurrentEpoch: 1, StartHeight: 1, EndHeight: 10, ValidatorSetId: 1})
	store.put(t, KeyForEpochValidator(1, first), &Validator{Address: first, StakedAmount: 1, Committees: []uint64{1}})
	store.put(t, KeyForEpochValidator(1, second), &Validator{Address: second, StakedAmount: 99, Committees: []uint64{1}})

	txHash := bytes.Repeat([]byte{0x31}, 32)
	requester := bytes.Repeat([]byte{0x32}, 20)
	message := &MessageObserveDeposit{ObserverAddress: first, SettlementDomainId: testSettlementDomainID(), ChainTxHash: txHash, Requester: requester, AmountMicros: 100, TokenAmount: []byte{100}}
	if response := contract.deliverObserveDeposit(5, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if _, found := store.values[string(KeyForDeposit(testSettlementDomainID(), txHash))]; found {
		t.Fatal("below-quorum epoch-one observation committed a deposit")
	}

	store.put(t, KeyForEpochClock(), &EpochClock{CurrentEpoch: 2, StartHeight: 11, EndHeight: 20, ValidatorSetId: 2})
	store.put(t, KeyForEpochValidator(2, first), &Validator{Address: first, StakedAmount: 99, Committees: []uint64{1}})
	store.put(t, KeyForEpochValidator(2, second), &Validator{Address: second, StakedAmount: 1, Committees: []uint64{1}})
	message.ObserverAddress = second
	if response := contract.deliverObserveDeposit(11, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if _, found := store.values[string(KeyForDeposit(testSettlementDomainID(), txHash))]; found {
		t.Fatal("epoch-one vote was combined with epoch-two voting power")
	}

	message.ObserverAddress = first
	if response := contract.deliverObserveDeposit(12, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if _, found := store.values[string(KeyForDeposit(testSettlementDomainID(), txHash))]; !found {
		t.Fatal("fresh epoch-two quorum did not commit the deposit")
	}
}

func TestProvisionalDepositReorgOrphansOnlyBackedRequests(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	requester := bytes.Repeat([]byte{4}, 20)
	txHash := bytes.Repeat([]byte{7}, 32)
	store.put(t, KeyForDeposit(testSettlementDomainID(), txHash), &DepositRecord{SettlementDomainId: testSettlementDomainID(),
		ChainTxHash: txHash, Requester: requester, Amount: 100, ObservedHeight: 10, Status: "provisional",
	})
	store.put(t, KeyForCredit(testSettlementDomainID(), requester), &CreditAccount{SettlementDomainId: testSettlementDomainID(),
		Requester: requester, Deposited: 100, Reserved: 60, Settled: 20,
		Released: 20, Provisional: 100, ProvisionalReserved: 60,
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), "settled"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "settled", Requester: requester, Budget: 40, Spent: 20,
		Status: "released", ReservedHeight: 11, ProvisionalBudget: 40,
	})
	store.put(t, KeyForProvisionalReservation(testSettlementDomainID(), requester, "settled"), &ReplayMarker{Id: []byte("settled")})
	store.put(t, KeyForRequest("settled"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "settled", Requester: requester, Status: "settled",
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), "active"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "active", Requester: requester, Budget: 60, Status: "reserved",
		ReservedHeight: 12, ProvisionalBudget: 60,
	})
	store.put(t, KeyForProvisionalReservation(testSettlementDomainID(), requester, "active"), &ReplayMarker{Id: []byte("active")})
	store.put(t, KeyForRequest("active"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "active", Requester: requester, Status: "authorized",
	})
	message := &MessageResolveDeposit{SettlementDomainId: testSettlementDomainID(), ObserverAddress: first, ChainTxHash: txHash, Resolution: "reorged"}
	if response := contract.deliverResolveDeposit(20, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	message.ObserverAddress = second
	if response := contract.deliverResolveDeposit(21, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	credit := new(CreditAccount)
	if found, err := contract.read(KeyForCredit(testSettlementDomainID(), requester), credit); err != nil || !found {
		t.Fatalf("credit missing: found=%v err=%v", found, err)
	}
	if credit.Deposited != 0 || credit.Reserved != 0 || credit.Settled != 0 || credit.Provisional != 0 || credit.Reorged != 100 {
		t.Fatalf("unexpected reorged credit: %#v", credit)
	}
	for _, requestID := range []string{"active", "settled"} {
		request := new(RequestRecord)
		if found, err := contract.read(KeyForRequest(requestID), request); err != nil || !found || request.Status != "orphaned_reorg" {
			t.Fatalf("request %s was not orphaned: found=%v status=%q err=%v", requestID, found, request.Status, err)
		}
		if found, err := contract.read(KeyForProvisionalReservation(testSettlementDomainID(), requester, requestID), new(ReplayMarker)); err != nil || found {
			t.Fatalf("provisional index for %s remains: found=%v err=%v", requestID, found, err)
		}
	}
}

func TestSettlementReorgPreservesRequesterAccountingAndReopensExecution(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	requester := bytes.Repeat([]byte{4}, 20)
	settlementHash := bytes.Repeat([]byte{8}, 32)
	store.put(t, KeyForCredit(testSettlementDomainID(), requester), &CreditAccount{SettlementDomainId: testSettlementDomainID(), Requester: requester, Deposited: 100, Settled: 20, Released: 20})
	store.put(t, KeyForRequest("request"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "request", InputHash: bytes.Repeat([]byte{0xaa}, 32), Requester: requester, Status: "settled",
		RequestArchiveId: testRequestArchiveID,
		SettlementTxHash: settlementHash,
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), "request"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "request", Requester: requester, Budget: 40, Spent: 20, Released: 20, Status: "released",
	})
	store.put(t, KeyForExecution("execution"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(),
		ExecutionId: "execution", RequestId: "request", Settled: true, SettlementTxHash: settlementHash,
	})
	message := &MessageResolveSettlement{SettlementDomainId: testSettlementDomainID(),
		ObserverAddress: first, RequestId: "request", SettlementTxHash: settlementHash,
		ExecutionIds: []string{"execution"}, FinalizesRequest: true,
	}
	if response := contract.deliverResolveSettlement(20, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	message.ObserverAddress = second
	if response := contract.deliverResolveSettlement(21, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	credit := new(CreditAccount)
	if found, err := contract.read(KeyForCredit(testSettlementDomainID(), requester), credit); err != nil || !found || credit.Settled != 20 || credit.Reserved != 0 || credit.Released != 20 {
		t.Fatalf("requester accounting changed during operator repair: found=%v credit=%#v err=%v", found, credit, err)
	}
	request := new(RequestRecord)
	if found, err := contract.read(KeyForRequest("request"), request); err != nil || !found || request.Status != "ready" || len(request.SettlementTxHash) != 0 {
		t.Fatalf("settlement was not made retryable: found=%v request=%#v err=%v", found, request, err)
	}
	execution := new(ExecutionRecord)
	if found, err := contract.read(KeyForExecution("execution"), execution); err != nil || !found || execution.Settled || len(execution.SettlementTxHash) != 0 {
		t.Fatalf("execution was not made retryable: found=%v execution=%#v err=%v", found, execution, err)
	}
	repairHash := bytes.Repeat([]byte{9}, 32)
	repair := &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(), RequestId: "request", SettlementTxHash: repairHash, ReservedBudget: 40, RequestSpent: 20, ExecutionIds: []string{"execution"}, FinalizesRequest: true}
	for _, observer := range [][]byte{first, second} {
		repair.ObserverAddress = observer
		if response := contract.deliverFinalizeRequest(22, repair); response.Error != nil {
			t.Fatal(response.Error)
		}
	}
	_, _ = contract.read(KeyForCredit(testSettlementDomainID(), requester), credit)
	_, _ = contract.read(KeyForRequest("request"), request)
	reservation := new(ReservationRecord)
	_, _ = contract.read(KeyForReservation(testSettlementDomainID(), "request"), reservation)
	if request.Status != "settled" || !bytes.Equal(request.SettlementTxHash, repairHash) || reservation.Status != "released" ||
		credit.Settled != 20 || credit.Released != 20 || credit.Reserved != 0 {
		t.Fatalf("repair changed requester accounting: request=%#v reservation=%#v credit=%#v", request, reservation, credit)
	}
}

func TestPartialSettlementReorgOnlyReopensItsExecution(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	requester := bytes.Repeat([]byte{5}, 20)
	reorgedHash, canonicalHash := bytes.Repeat([]byte{8}, 32), bytes.Repeat([]byte{9}, 32)
	store.put(t, KeyForCredit(testSettlementDomainID(), requester), &CreditAccount{SettlementDomainId: testSettlementDomainID(), Requester: requester, Deposited: 100, Settled: 40, Released: 60})
	store.put(t, KeyForRequest("request"), &RequestRecord{SettlementDomainId: testSettlementDomainID(), RequestId: "request", Requester: requester, Status: "settled", SettlementTxHash: canonicalHash})
	store.put(t, KeyForReservation(testSettlementDomainID(), "request"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: "request", Requester: requester, Budget: 100, Spent: 40, Released: 60, Status: "released"})
	store.put(t, KeyForExecution("execution-a"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(), ExecutionId: "execution-a", RequestId: "request", Settled: true, SettlementTxHash: reorgedHash})
	store.put(t, KeyForExecution("execution-b"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(), ExecutionId: "execution-b", RequestId: "request", Settled: true, SettlementTxHash: canonicalHash})
	message := &MessageResolveSettlement{SettlementDomainId: testSettlementDomainID(), ObserverAddress: first, RequestId: "request", SettlementTxHash: reorgedHash, ExecutionIds: []string{"execution-a"}}
	if response := contract.deliverResolveSettlement(20, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	message.ObserverAddress = second
	if response := contract.deliverResolveSettlement(21, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	firstExecution, secondExecution := new(ExecutionRecord), new(ExecutionRecord)
	_, _ = contract.read(KeyForExecution("execution-a"), firstExecution)
	_, _ = contract.read(KeyForExecution("execution-b"), secondExecution)
	if firstExecution.Settled || len(firstExecution.SettlementTxHash) != 0 || !secondExecution.Settled || !bytes.Equal(secondExecution.SettlementTxHash, canonicalHash) {
		t.Fatalf("partial rollback touched the wrong execution: first=%#v second=%#v", firstExecution, secondExecution)
	}
	request := new(RequestRecord)
	_, _ = contract.read(KeyForRequest("request"), request)
	if request.Status != "ready" || !bytes.Equal(request.SettlementTxHash, canonicalHash) {
		t.Fatalf("finalized request was not opened for a repair settlement: %#v", request)
	}
}

func TestAdversarialExecutionRejectsDuplicatesAndRevokedEnclave(t *testing.T) {
	contract, store, first, _ := newMemoryContract(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyDigest := sha256.Sum256(publicKey)
	keyID := "ed25519:" + hex.EncodeToString(keyDigest[:])
	store.put(t, KeyForEnclave(keyID), &EnclaveKey{OwnerAddress: first, PublicKey: publicKey, TeeKeyId: keyID, Active: true})
	store.put(t, KeyForServicer(first), &Servicer{OwnerAddress: first, TeeKeyId: keyID, Models: []string{"model"}, Bond: 100, Active: true})
	inputHash := sha256.Sum256([]byte("input"))
	putRequest := func(id string) {
		executionID := assignmentExecutionID(id, "model", 0, first, inputHash[:])
		store.put(t, KeyForRequest(id), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
			RequestId: id, InputHash: inputHash[:], Requester: first,
			OutputType: "boolean", Models: []string{"model"}, ExecutionQuorum: 1, DeadlineHeight: 30,
			Assignments: []*Assignment{{Model: "model", Provider: "provider", ServicerAddress: first, DeadlineHeight: 30, ExecutionId: executionID, TeeKeyId: keyID, MaxProviderCost: 100}}, Status: "authorized",
		})
		store.put(t, KeyForReservation(testSettlementDomainID(), id), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: id, Requester: first, Budget: 100, Status: "reserved"})
	}
	putRequest("request-1")
	shopped := signedExecution(t, privateKey, publicKey, keyID, first, "request-1", "exec:servicer-chosen", inputHash)
	if response := contract.deliverSubmitExecution(19, shopped); response.Error != nil {
		t.Fatalf("invalid signed evidence was not committed for slashing: %v", response.Error)
	}
	servicer := new(Servicer)
	if found, err := contract.read(KeyForServicer(first), servicer); err != nil || !found || servicer.FailureCount != 1 {
		t.Fatalf("invalid receipt did not penalize servicer: found=%v failures=%d err=%v", found, servicer.FailureCount, err)
	}
	message := signedExecution(t, privateKey, publicKey, keyID, first, "request-1", assignmentExecutionID("request-1", "model", 0, first, inputHash[:]), inputHash)
	if response := contract.deliverSubmitExecution(20, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := contract.deliverSubmitExecution(21, message); response.Error != nil {
		t.Fatalf("exact execution replay was not idempotent: %v", response.Error)
	}
	conflict := proto.Clone(message).(*MessageSubmitExecution)
	conflict.Signature[0] ^= 1
	if response := contract.deliverSubmitExecution(21, conflict); response.Error == nil {
		t.Fatal("conflicting execution replay was accepted")
	}
	putRequest("request-late")
	late := signedExecution(t, privateKey, publicKey, keyID, first, "request-late", assignmentExecutionID("request-late", "model", 0, first, inputHash[:]), inputHash)
	if response := contract.deliverSubmitExecution(31, late); response.Error == nil {
		t.Fatal("execution submitted after its assignment deadline was accepted")
	}

	putRequest("request-2")
	store.put(t, KeyForEnclave(keyID), &EnclaveKey{OwnerAddress: first, PublicKey: publicKey, TeeKeyId: keyID, Active: false})
	revoked := signedExecution(t, privateKey, publicKey, keyID, first, "request-2", "execution-2", inputHash)
	if response := contract.deliverSubmitExecution(22, revoked); response.Error == nil {
		t.Fatal("receipt signed by a revoked enclave key was accepted")
	}
}

func TestAdversarialSettlementAndBridgeReplay(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	requestID := "request"
	requester := bytes.Repeat([]byte{4}, 20)
	store.put(t, KeyForRequest(requestID), &RequestRecord{SettlementDomainId: testSettlementDomainID(), RequestId: requestID, InputHash: bytes.Repeat([]byte{0xaa}, 32), Requester: requester, RequestArchiveId: testRequestArchiveID, Status: "ready", Assignments: []*Assignment{{Model: "model", Completed: true, ExecutionId: "execution"}}})
	store.put(t, KeyForExecution("execution"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(), ExecutionId: "execution", RequestId: requestID, Model: "model", Cost: 40})
	store.put(t, KeyForReservation(testSettlementDomainID(), requestID), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: requestID, Requester: requester, Budget: 100, Spent: 40, Status: "reserved"})
	store.put(t, KeyForCredit(testSettlementDomainID(), requester), &CreditAccount{SettlementDomainId: testSettlementDomainID(), Requester: requester, Deposited: 100, Reserved: 100})
	store.put(t, KeyForSettlementIndex(requestID), &RequestRecord{SettlementDomainId: testSettlementDomainID(), RequestId: requestID})
	storedReservation := new(ReservationRecord)
	if found, err := contract.read(KeyForReservation(testSettlementDomainID(), requestID), storedReservation); err != nil || !found || storedReservation.Spent != 40 {
		t.Fatalf("reservation fixture was not stored: found=%v err=%v reservation=%#v", found, err, storedReservation)
	}
	message := &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(),
		ObserverAddress: first, RequestId: requestID, SettlementTxHash: bytes.Repeat([]byte{5}, 32),
		ReservedBudget: 100, RequestSpent: 40, ExecutionIds: []string{"execution"}, FinalizesRequest: true,
	}
	if response := contract.deliverFinalizeRequest(30, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if _, found := store.values[string(KeyForSettlementIndex(requestID))]; !found {
		t.Fatal("minority settlement observation removed request discovery index")
	}
	message.ObserverAddress = second
	if response := contract.deliverFinalizeRequest(31, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := contract.deliverFinalizeRequest(32, message); response.Error == nil {
		t.Fatal("settlement finalization replay was accepted")
	}

	params := defaultProtocolParams()
	params.Revision, params.CanonicalChainId, params.ValidatorSetId = 1, 8453, 1
	params.CanonicalTokenAddress = bytes.Repeat([]byte{7}, 20)
	params.CanonicalBridgeAddress = bytes.Repeat([]byte{8}, 20)
	params.TreasuryAddress = bytes.Repeat([]byte{9}, 20)
	store.put(t, KeyForProtocolParams(), params)
	lock := &MessageObserveBridgeLock{
		ObserverAddress: first, CanonicalChainTxHash: bytes.Repeat([]byte{10}, 32), Nonce: 1,
		CanonicalChainSender: bytes.Repeat([]byte{11}, 20), Recipient: requester, Amount: 10,
	}
	if response := contract.deliverObserveBridgeLock(40, lock); response.Error != nil {
		t.Fatal(response.Error)
	}
	lock.ObserverAddress = second
	if response := contract.deliverObserveBridgeLock(41, lock); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := contract.deliverObserveBridgeLock(42, lock); response.Error == nil {
		t.Fatal("Base bridge lock replay was accepted")
	}
	burnID := bytes.Repeat([]byte{12}, 32)
	if response := contract.deliverBurnBridge(43, &MessageBurnBridge{
		OwnerAddress: requester, CanonicalChainRecipient: bytes.Repeat([]byte{13}, 20), Amount: 5, BurnId: burnID,
	}); response.Error != nil {
		t.Fatal(response.Error)
	}
	if response := contract.deliverBurnBridge(44, &MessageBurnBridge{
		OwnerAddress: requester, CanonicalChainRecipient: bytes.Repeat([]byte{13}, 20), Amount: 5, BurnId: burnID,
	}); response.Error == nil {
		t.Fatal("Canopy bridge burn replay was accepted")
	}
	// A burn retains its originating set, but a later committee must be able to
	// certify and observe the immutable release after rotation.
	params.ValidatorSetId = 2
	store.put(t, KeyForProtocolParams(), params)
	release := &MessageObserveBridgeRelease{
		ObserverAddress: first, BurnId: burnID, CanonicalChainTxHash: bytes.Repeat([]byte{14}, 32),
		Nonce: 1, CanonicalChainRecipient: bytes.Repeat([]byte{13}, 20), Amount: 5, ValidatorSetId: 2,
	}
	if response := contract.deliverObserveBridgeRelease(45, release); response.Error != nil {
		t.Fatal(response.Error)
	}
	release.ObserverAddress = second
	if response := contract.deliverObserveBridgeRelease(46, release); response.Error != nil {
		t.Fatal(response.Error)
	}
	committedBurn := new(BridgeBurn)
	if found, err := contract.read(KeyForBridgeBurn(burnID), committedBurn); err != nil || !found || committedBurn.Status != "released" || committedBurn.ValidatorSetId != 1 || committedBurn.ReleaseValidatorSetId != 2 {
		t.Fatalf("bridge release status = %q, found = %v, err = %v", committedBurn.Status, found, err)
	}
}

func TestProducerPayoutRequiresBoundedConsensusIdentity(t *testing.T) {
	contract, store, first, _ := newMemoryContract(t)
	unknown := bytes.Repeat([]byte{0x71}, 20)
	baseAddress := bytes.Repeat([]byte{0x72}, 20)
	if response := contract.deliverSetProducerPayout(&MessageSetProducerPayout{OwnerAddress: unknown, CanonicalChainAddress: baseAddress}); response.Error == nil {
		t.Fatal("unknown self-signed identity created permanent payout state")
	}
	if _, found := store.values[string(KeyForProducerPayout(unknown))]; found {
		t.Fatal("unauthorized payout state was written")
	}

	if response := contract.deliverSetProducerPayout(&MessageSetProducerPayout{OwnerAddress: first, CanonicalChainAddress: baseAddress}); response.Error != nil {
		t.Fatalf("current validator payout rejected: %v", response.Error)
	}
	store.put(t, KeyForProducerIdentity(unknown), &ProducerIdentity{OwnerAddress: unknown})
	if response := contract.deliverSetProducerPayout(&MessageSetProducerPayout{OwnerAddress: unknown, CanonicalChainAddress: baseAddress}); response.Error != nil {
		t.Fatalf("proven producer payout rejected: %v", response.Error)
	}
}

func TestExecutionSettlementDoesNotWaitForRequestPeers(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	requestID := "incremental"
	requester := bytes.Repeat([]byte{14}, 20)
	store.put(t, KeyForRequest(requestID), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: requestID, InputHash: bytes.Repeat([]byte{0xaa}, 32), Requester: requester, RequestArchiveId: testRequestArchiveID, Status: "ready",
		Assignments: []*Assignment{{Model: "a", Completed: true, ExecutionId: "execution-a"}, {Model: "b", Completed: true, ExecutionId: "execution-b"}},
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), requestID), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: requestID, Requester: requester, Budget: 100, Spent: 40, Status: "reserved"})
	store.put(t, KeyForCredit(testSettlementDomainID(), requester), &CreditAccount{SettlementDomainId: testSettlementDomainID(), Requester: requester, Deposited: 100, Reserved: 100})
	store.put(t, KeyForExecution("execution-a"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(), ExecutionId: "execution-a", RequestId: requestID, Model: "a", Cost: 20})
	store.put(t, KeyForExecution("execution-b"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(), ExecutionId: "execution-b", RequestId: requestID, Model: "b", Cost: 20})

	partial := &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(), RequestId: requestID, SettlementTxHash: bytes.Repeat([]byte{15}, 32), ReservedBudget: 100, RequestSpent: 40, ExecutionIds: []string{"execution-a"}}
	for _, observer := range [][]byte{first, second} {
		partial.ObserverAddress = observer
		if response := contract.deliverFinalizeRequest(40, partial); response.Error != nil {
			t.Fatal(response.Error)
		}
	}
	execution := new(ExecutionRecord)
	request := new(RequestRecord)
	reservation := new(ReservationRecord)
	_, _ = contract.read(KeyForExecution("execution-a"), execution)
	_, _ = contract.read(KeyForRequest(requestID), request)
	_, _ = contract.read(KeyForReservation(testSettlementDomainID(), requestID), reservation)
	if !execution.Settled || request.Status != "ready" || reservation.Status != "reserved" {
		t.Fatalf("partial settlement closed request: execution=%#v request=%#v reservation=%#v", execution, request, reservation)
	}

	final := &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(), RequestId: requestID, SettlementTxHash: bytes.Repeat([]byte{16}, 32), ReservedBudget: 100, RequestSpent: 40, ExecutionIds: []string{"execution-b"}, FinalizesRequest: true}
	for _, observer := range [][]byte{first, second} {
		final.ObserverAddress = observer
		if response := contract.deliverFinalizeRequest(41, final); response.Error != nil {
			t.Fatal(response.Error)
		}
	}
	_, _ = contract.read(KeyForRequest(requestID), request)
	_, _ = contract.read(KeyForReservation(testSettlementDomainID(), requestID), reservation)
	if request.Status != "settled" || reservation.Status != "released" || reservation.Released != 60 {
		t.Fatalf("final execution did not close request: request=%#v reservation=%#v", request, reservation)
	}
}

func TestSettlementFinalizationRejectsMissingRequestArchive(t *testing.T) {
	contract, store, first, _ := newMemoryContract(t)
	requester := bytes.Repeat([]byte{19}, 20)
	store.put(t, KeyForRequest("unarchived"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "unarchived", Requester: requester, Status: "ready",
		Assignments: []*Assignment{{Model: "model", Completed: true, ExecutionId: "execution"}},
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), "unarchived"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: "unarchived", Requester: requester, Budget: 1, Status: "reserved"})
	store.put(t, KeyForExecution("execution"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(), ExecutionId: "execution", RequestId: "unarchived", Model: "model"})
	message := &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(),
		ObserverAddress: first, RequestId: "unarchived", SettlementTxHash: bytes.Repeat([]byte{20}, 32),
		ReservedBudget: 1, ExecutionIds: []string{"execution"}, FinalizesRequest: true,
	}
	if response := contract.deliverFinalizeRequest(1, message); response.Error == nil {
		t.Fatal("request without archived input evidence was finalized")
	}
}

func TestReassignmentRetryLimitAtomicallyReleasesAndSlashes(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	requester := bytes.Repeat([]byte{4}, 20)
	servicerAddress := bytes.Repeat([]byte{5}, 20)
	params := defaultProtocolParams()
	params.Revision, params.RetryLimit, params.TimeoutSlashBps = 1, 1, 1_000
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForServicer(servicerAddress), &Servicer{
		OwnerAddress: servicerAddress, Models: []string{"model"}, Bond: 100, Active: true,
	})
	store.put(t, KeyForRequest("expired"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "expired", InputHash: bytes.Repeat([]byte{6}, 32), Requester: requester,
		Models: []string{"model"}, DeadlineHeight: 10,
		Assignments: []*Assignment{{Model: "model", ServicerAddress: servicerAddress, Attempt: 1, DeadlineHeight: 10}},
		Status:      "authorized",
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), "expired"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "expired", Requester: requester, Budget: 100, Status: "reserved",
	})
	store.put(t, KeyForCredit(testSettlementDomainID(), requester), &CreditAccount{SettlementDomainId: testSettlementDomainID(), Requester: requester, Deposited: 100, Reserved: 100})

	message := &MessageReassignRequest{
		ObserverAddress: first, RequestId: "expired", Model: "model", NewDeadlineHeight: 50,
	}
	if response := contract.deliverReassignRequest(20, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	request := new(RequestRecord)
	if found, err := contract.read(KeyForRequest("expired"), request); err != nil || !found || request.Status != "authorized" {
		t.Fatalf("one observation changed the request: found=%v status=%q err=%v", found, request.Status, err)
	}

	message.ObserverAddress = second
	if response := contract.deliverReassignRequest(21, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if found, err := contract.read(KeyForRequest("expired"), request); err != nil || !found || request.Status != "ready" || request.Assignments[0].TerminalStatus != "failed" {
		t.Fatalf("request was not ready with a terminal failure: found=%v record=%#v err=%v", found, request, err)
	}
	reservation := new(ReservationRecord)
	if found, err := contract.read(KeyForReservation(testSettlementDomainID(), "expired"), reservation); err != nil || !found ||
		reservation.Status != "reserved" || reservation.Released != 0 {
		t.Fatalf("reservation changed before Base failure publication: found=%v record=%#v err=%v", found, reservation, err)
	}
	credit := new(CreditAccount)
	if found, err := contract.read(KeyForCredit(testSettlementDomainID(), requester), credit); err != nil || !found || credit.Reserved != 100 || credit.Settled != 0 || credit.Released != 0 {
		t.Fatalf("credit reservation changed before Base failure publication: found=%v record=%#v err=%v", found, credit, err)
	}
	servicer := new(Servicer)
	if found, err := contract.read(KeyForServicer(servicerAddress), servicer); err != nil || !found || servicer.FailureCount != 1 {
		t.Fatalf("servicer failure was not recorded: found=%v record=%#v err=%v", found, servicer, err)
	}
	evidenceID := hashFields([]byte("takusen:timeout"), []byte("expired"), []byte("model"), uint32Bytes(2))
	evidence := new(SlashEvidence)
	if found, err := contract.read(KeyForSlashEvidence(evidenceID), evidence); err != nil || !found ||
		evidence.Status != "queued" || evidence.Penalty != 10 || !bytes.Equal(evidence.TargetAddress, servicerAddress) {
		t.Fatalf("timeout slash was not queued: found=%v record=%#v err=%v", found, evidence, err)
	}
	records := make(map[string]proto.Message)
	deletes, _, applyErr := contract.applyEpochSlashes(2, params, records, 100)
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	if writeErr := contract.writeChanges(records, deletes); writeErr != nil {
		t.Fatal(writeErr)
	}
	if found, err := contract.read(KeyForServicer(servicerAddress), servicer); err != nil || !found || servicer.Bond != 90 {
		t.Fatalf("automatic timeout slash was not applied at the next epoch: found=%v servicer=%#v err=%v", found, servicer, err)
	}
}

func TestReassignmentWaitsForEligibleServicerWithoutExhaustingRetries(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	requester := bytes.Repeat([]byte{4}, 20)
	previousAddress := bytes.Repeat([]byte{5}, 20)
	replacementAddress := bytes.Repeat([]byte{6}, 20)
	params := defaultProtocolParams()
	params.Revision, params.RetryLimit, params.TimeoutSlashBps = 1, 3, 1_000
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForServicer(previousAddress), &Servicer{OwnerAddress: previousAddress, Models: []string{"model"}, Bond: 100})
	store.put(t, KeyForRequest("waiting"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "waiting", InputHash: bytes.Repeat([]byte{7}, 32), Requester: requester, Models: []string{"model"}, DeadlineHeight: 10,
		Assignments: []*Assignment{{Model: "model", Provider: "provider", TeeKeyId: "old-key", ExecutionId: "old-execution", ServicerAddress: previousAddress, DeadlineHeight: 10}},
		Status:      "authorized",
	})

	waiting := &MessageReassignRequest{RequestId: "waiting", Model: "model", NewDeadlineHeight: 50}
	for _, observer := range [][]byte{first, second} {
		waiting.ObserverAddress = observer
		if response := contract.deliverReassignRequest(20, waiting); response.Error != nil {
			t.Fatal(response.Error)
		}
	}
	request := new(RequestRecord)
	_, _ = contract.read(KeyForRequest("waiting"), request)
	assignment := request.Assignments[0]
	if assignment.Completed || assignment.Attempt != 0 || assignment.TerminalStatus != "awaiting_servicer" || assignment.DeadlineHeight != 50 {
		t.Fatalf("transient servicer absence exhausted work: %#v", assignment)
	}

	store.put(t, KeyForServicer(replacementAddress), &Servicer{OwnerAddress: replacementAddress, Models: []string{"model"}, TeeKeyId: "new-key", Bond: 100, Active: true})
	store.put(t, KeyForEnclave("new-key"), &EnclaveKey{OwnerAddress: replacementAddress, TeeKeyId: "new-key", Active: true})
	retry := &MessageReassignRequest{RequestId: "waiting", Model: "model", NewDeadlineHeight: 100}
	for _, observer := range [][]byte{first, second} {
		retry.ObserverAddress = observer
		if response := contract.deliverReassignRequest(60, retry); response.Error != nil {
			t.Fatal(response.Error)
		}
	}
	_, _ = contract.read(KeyForRequest("waiting"), request)
	assignment = request.Assignments[0]
	if assignment.Completed || assignment.Attempt != 1 || assignment.TerminalStatus != "" || !bytes.Equal(assignment.ServicerAddress, replacementAddress) {
		t.Fatalf("waiting assignment was not resumed: %#v", assignment)
	}
}

func TestEpochAppliesStakeUnbondingBaseRewardsAndSlashing(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.UnbondingEpochs = 1, 10, 1
	params.EmissionPerEpoch, params.TreasuryBps = 1_000, 1_000
	params.TimeoutSlashBps, params.InvalidReceiptSlashBps = 1_000, 5_000
	params.CanonicalChainId, params.ValidatorSetId = 8453, 1
	params.CanonicalTokenAddress = bytes.Repeat([]byte{7}, 20)
	params.CanonicalBridgeAddress = bytes.Repeat([]byte{8}, 20)
	params.TreasuryAddress = bytes.Repeat([]byte{9}, 20)
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForServicer(first), &Servicer{OwnerAddress: first, Bond: 100, Active: true})
	store.put(t, KeyForAccount(first), &Account{Address: first, Amount: 50})

	if response := contract.deliverQueueServicerStake(1, &MessageQueueServicerStake{OwnerAddress: first, TargetBond: 60, Active: true, AutoCompound: true}); response.Error == nil {
		t.Fatal("Canopy-only reward compounding was accepted")
	}
	queue := &MessageQueueServicerStake{OwnerAddress: first, TargetBond: 60, Active: true}
	if response := contract.deliverQueueServicerStake(1, queue); response.Error != nil {
		t.Fatal(response.Error)
	}
	seedRotation := func(oldSetID uint64) {
		t.Helper()
		clock := new(EpochClock)
		if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found {
			t.Fatal("epoch clock is unavailable")
		}
		if len(clock.ValidatorHandoffDomains) == 0 {
			clock.ValidatorHandoffDomains = authorityHandoffDomains(params)
		}
		if clock.ValidatorHandoffAttempt == 0 {
			clock.ValidatorHandoffAttempt = 1
		}
		clock.ValidatorHandoffTimestamp = clock.ConsensusTimeSeconds
		clock.ValidatorHandoffOutgoingAuthorityCutoff = clock.ValidatorHandoffTimestamp
		store.put(t, KeyForEpochClock(), clock)
		proofID := hashFields([]byte("rotation"), uint64Bytes(oldSetID))
		store.put(t, KeyForQuorumProof(proofID), &QuorumProof{
			ProofKind: "validator-set-rotation-queued", ProofId: proofID,
			ValidatorSetId: oldSetID, NewValidatorSetId: oldSetID + 1, CompletedHeight: oldSetID,
			SettlementDomainId: params.SettlementDomains[0].Id,
			HandoffGeneration:  validatorHandoffGeneration(clock), HandoffTimestamp: clock.ValidatorHandoffTimestamp,
		})
		store.put(t, KeyForQueuedRotationIndex(params.SettlementDomains[0].Id, oldSetID, oldSetID+1), &ReplayMarker{Id: proofID})
	}
	if response := contract.endBlock(epochEndRequest(10, first)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("epoch-one boundary preparation = %#v", response)
	}
	seedRotation(1)
	if response := contract.endBlock(epochEndRequest(11, first)); response.Error != nil {
		t.Fatal(response.Error)
	}
	servicer := new(Servicer)
	if found, err := contract.read(KeyForServicer(first), servicer); err != nil || !found {
		t.Fatal(err)
	}
	if servicer.Bond != 60 || servicer.AutoCompound || servicer.AccruedRewards != 900 {
		t.Fatalf("servicer after epoch = %#v", servicer)
	}
	unbonding := new(UnbondingRecord)
	if found, err := contract.read(KeyForUnbonding(first, 1), unbonding); err != nil || !found || unbonding.Amount != 40 || unbonding.ReleaseEpoch != 2 {
		t.Fatalf("unbonding = %#v, found = %v, err = %v", unbonding, found, err)
	}
	epoch := new(EpochAuthorization)
	if found, err := contract.read(KeyForEpochAuthorization(1), epoch); err != nil || !found ||
		epoch.CompoundedAmount != 0 || epoch.ProducerAmount != 900 || epoch.TreasuryAmount != 100 || epoch.TotalAmount != 1_000 || len(epoch.CanonicalChainDigest) != 32 {
		t.Fatalf("epoch authorization = %#v, found = %v, err = %v", epoch, found, err)
	}

	if response := contract.endBlock(epochEndRequest(21, first)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("epoch-two preparation = %#v", response)
	}
	seedRotation(2)
	if response := contract.endBlock(epochEndRequest(22, first)); response.Error != nil {
		t.Fatal(response.Error)
	}
	// Core installs the newly activated frozen roster at the next BeginBlock.
	store.put(t, KeyForEpochValidator(3, first), &Validator{Address: first, StakedAmount: 100, Committees: []uint64{1}})
	store.put(t, KeyForEpochValidator(3, second), &Validator{Address: second, StakedAmount: 100, Committees: []uint64{1}})
	if response := contract.deliverWithdrawUnbonded(20, &MessageWithdrawUnbonded{OwnerAddress: first, Sequence: 1}); response.Error != nil {
		t.Fatal(response.Error)
	}
	account := new(Account)
	if found, err := contract.read(KeyForAccount(first), account); err != nil || !found || account.Amount != 90 {
		t.Fatalf("withdrawn account = %#v, found = %v, err = %v", account, found, err)
	}

	evidenceID := bytes.Repeat([]byte{15}, 32)
	slash := &MessageObserveSlashEvidence{ObserverAddress: first, EvidenceId: evidenceID, TargetAddress: first, Reason: "timeout"}
	if response := contract.deliverObserveSlashEvidence(21, slash); response.Error != nil {
		t.Fatal(response.Error)
	}
	slash.ObserverAddress = second
	if response := contract.deliverObserveSlashEvidence(22, slash); response.Error != nil {
		t.Fatal(response.Error)
	}
	queued := new(SlashEvidence)
	if found, err := contract.read(KeyForSlashEvidence(evidenceID), queued); err != nil || !found || queued.Status != "queued" || queued.Penalty == 0 {
		t.Fatalf("queued slash = %#v, found = %v, err = %v", queued, found, err)
	}
	if response := contract.endBlock(epochEndRequest(32, first)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("epoch-three preparation = %#v", response)
	}
	seedRotation(3)
	if response := contract.endBlock(epochEndRequest(33, first)); response.Error != nil {
		t.Fatal(response.Error)
	}
	applied := new(SlashEvidence)
	if found, err := contract.read(KeyForSlashEvidence(evidenceID), applied); err != nil || !found || applied.Status != "applied" {
		t.Fatalf("applied slash = %#v, found = %v, err = %v", applied, found, err)
	}
}

func TestEpochClockKeepsMonotonicEpochsAcrossGovernedDurationChange(t *testing.T) {
	contract, store, first, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	store.put(t, KeyForProtocolParams(), params)
	if response := contract.endBlock(epochEndRequest(10, first)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("epoch-one boundary preparation = %#v", response)
	}
	seedQueuedRotation(t, store, params, 1)
	if response := contract.endBlock(epochEndRequest(11, first)); response.Error != nil {
		t.Fatal(response.Error)
	}

	params = proto.Clone(params).(*ProtocolParams)
	params.Revision, params.EpochBlocks = 2, 25
	store.put(t, KeyForProtocolParams(), params)
	if response := contract.endBlock(epochEndRequest(21, first)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("epoch-two preparation = %#v", response)
	}
	seedQueuedRotation(t, store, params, 2)
	if response := contract.endBlock(epochEndRequest(22, first)); response.Error != nil {
		t.Fatal(response.Error)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found {
		t.Fatalf("epoch clock missing: found=%v err=%v", found, err)
	}
	if clock.CurrentEpoch != 3 || clock.StartHeight != 23 || clock.EndHeight != 47 || clock.ValidatorSetId != 3 {
		t.Fatalf("epoch clock after duration change = %#v", clock)
	}
	if response := contract.endBlock(epochEndRequest(47, first)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("epoch-three preparation = %#v", response)
	}
	seedQueuedRotation(t, store, params, 3)
	if response := contract.endBlock(epochEndRequest(48, first)); response.Error != nil {
		t.Fatal(response.Error)
	}
	for epoch := uint64(1); epoch <= 3; epoch++ {
		authorization := new(EpochAuthorization)
		if found, err := contract.read(KeyForEpochAuthorization(epoch), authorization); err != nil || !found || authorization.Epoch != epoch {
			t.Fatalf("epoch %d authorization: found=%v err=%v record=%#v", epoch, found, err, authorization)
		}
	}
}

func TestEpochEndSignalsCoreValidatorSetActivation(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	store.put(t, KeyForProtocolParams(), params)

	response := contract.endBlock(epochEndRequest(5, proposer))
	if response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("mid-epoch response = %#v", response)
	}
	response = contract.endBlock(epochEndRequest(10, proposer))
	if response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("epoch boundary preparation response = %#v error=%v", response, response.Error)
	}
	seedQueuedRotation(t, store, params, 1)
	response = contract.endBlock(epochEndRequest(11, proposer))
	if response.Error != nil || !response.ValidatorSetEpochEnd {
		t.Fatalf("epoch-boundary response = %#v", response)
	}
}

func TestUnchangedEpochRosterDoesNotRotateSettlementVerifiers(t *testing.T) {
	contract, store, first, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	store.put(t, KeyForProtocolParams(), params)
	response := contract.endBlock(epochEndRequestWithWeights(10, 10, first, 100, 100))
	if response.Error != nil || !response.ValidatorSetEpochEnd {
		t.Fatalf("unchanged epoch boundary = %#v", response)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.ValidatorSetId != 1 {
		t.Fatalf("unchanged roster advanced EVM set: %#v", clock)
	}
}

func TestObservedEpochMintClearsPendingIndex(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	params.EmissionPerEpoch, params.TreasuryBps = 100, 0
	params.CanonicalTokenAddress = bytes.Repeat([]byte{0x71}, 20)
	store.put(t, KeyForProtocolParams(), params)
	if response := contract.endBlock(epochEndRequestWithWeights(10, 10, first, 100, 100)); response.Error != nil {
		t.Fatal(response.Error)
	}
	if found, err := contract.read(KeyForPendingEpochAuthorization(1), new(ReplayMarker)); err != nil || !found {
		t.Fatalf("pending epoch index missing: %v", err)
	}
	message := &MessageObserveEpochMint{ObserverAddress: first, Epoch: 1, CanonicalChainTxHash: bytes.Repeat([]byte{0x72}, 32), ValidatorSetId: 1}
	if response := contract.deliverObserveEpochMint(11, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	message.ObserverAddress = second
	if response := contract.deliverObserveEpochMint(12, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if found, err := contract.read(KeyForPendingEpochAuthorization(1), new(ReplayMarker)); err != nil || found {
		t.Fatalf("minted epoch remained pending: found=%v err=%v", found, err)
	}
	authorization := new(EpochAuthorization)
	if found, err := contract.read(KeyForEpochAuthorization(1), authorization); err != nil || !found || authorization.Status != "minted" {
		t.Fatalf("epoch mint status = %#v err=%v", authorization, err)
	}
}

func TestEpochCreatesNextValidatorSetOnlyAtBoundary(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	store.put(t, KeyForProtocolParams(), params)

	response := contract.endBlock(epochEndRequest(7, proposer))
	if response.Error != nil || response.ValidatorSetEpochPrepare || response.ValidatorSetEpochEnd {
		t.Fatalf("pre-boundary block created a handoff = %#v", response)
	}
	response = contract.endBlock(epochEndRequest(10, proposer))
	if response.Error != nil || !response.ValidatorSetEpochPrepare || response.ValidatorSetEpochEnd {
		t.Fatalf("epoch-boundary snapshot response = %#v", response)
	}
	seedQueuedRotation(t, store, params, 1)
	response = contract.endBlock(epochEndRequest(11, proposer))
	if response.Error != nil || !response.ValidatorSetEpochEnd {
		t.Fatalf("ready handoff response = %#v", response)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.ValidatorSetId != 2 {
		t.Fatalf("validator set did not advance with epoch: found=%v err=%v clock=%#v", found, err, clock)
	}
}

func TestHandoffTimestampStartsFromActualBoundaryConsensusTime(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	params.ValidatorHandoffNoticeSeconds = 2_400
	store.put(t, KeyForProtocolParams(), params)

	if response := contract.endBlock(epochEndRequestAt(7, 100, proposer)); response.Error != nil || response.ValidatorSetEpochPrepare {
		t.Fatalf("pre-boundary block prepared a handoff = %#v", response)
	}
	if response := contract.endBlock(epochEndRequestAt(10, 10_000, proposer)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("boundary did not start a schedule attempt: %#v", response)
	}
	started := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), started); err != nil || !found ||
		started.ValidatorHandoffTimestamp != 12_400 || started.ValidatorHandoffAttempt != 1 {
		t.Fatalf("handoff did not use actual boundary time: found=%v err=%v clock=%#v", found, err, started)
	}
}

func TestValidatorHandoffGenerationVector(t *testing.T) {
	clock := &EpochClock{
		ValidatorHandoffNativeChainId: 1, CurrentEpoch: 7, ValidatorSetId: 11,
		ValidatorHandoffRosterHash:    bytes.Repeat([]byte{0x11}, 32),
		ValidatorHandoffDomainSetHash: bytes.Repeat([]byte{0x22}, 32),
		ValidatorHandoffAttempt:       3, ValidatorHandoffTimestamp: 1_700_000_000,
		ValidatorHandoffOutgoingAuthorityCutoff: 1_699_990_000,
	}
	const want = "2b15397b65e1d5d01e5f495ef83bedbd7954583d9715b49950022e04f4870c53"
	if got := hex.EncodeToString(validatorHandoffGeneration(clock)); got != want {
		t.Fatalf("generation = %s, want %s", got, want)
	}
}

func TestPreparedHandoffKeepsItsSettlementDomainSnapshot(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	second := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	second.Id = bytes.Repeat([]byte{0x93}, 32)
	second.ChainId = 56
	params.SettlementDomains = append(params.SettlementDomains, second)
	store.put(t, KeyForProtocolParams(), params)
	if response := contract.endBlock(epochEndRequest(10, proposer)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("boundary handoff preparation = %#v", response)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || len(clock.ValidatorHandoffDomains) != 2 {
		t.Fatalf("domain snapshot missing: found=%v err=%v clock=%#v", found, err, clock)
	}

	changed := proto.Clone(params).(*ProtocolParams)
	changed.Revision = 2
	changed.SettlementDomains[1].Active = false
	third := proto.Clone(changed.SettlementDomains[0]).(*SettlementDomain)
	third.Id = bytes.Repeat([]byte{0x94}, 32)
	third.ChainId = 137
	changed.SettlementDomains = append(changed.SettlementDomains, third)
	store.put(t, KeyForProtocolParams(), changed)

	if response := contract.endBlock(epochEndRequest(11, proposer)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("boundary did not create snapshotted attempt: %#v", response)
	}
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || len(clock.ValidatorHandoffDomains) != 2 ||
		!handoffIncludesDomain(clock, second.Id) || handoffIncludesDomain(clock, third.Id) {
		t.Fatalf("governance rewrote the prepared domain snapshot: found=%v err=%v clock=%#v", found, err, clock)
	}
}

func TestBoundarySnapshotIsImmuneToLaterRosterAndParameterChanges(t *testing.T) {
	contract, store, proposer, secondAddress := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	store.put(t, KeyForProtocolParams(), params)
	if response := contract.endBlock(epochEndRequestAt(10, 10_000, proposer)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("boundary preparation = %#v", response)
	}
	before := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), before); err != nil || !found {
		t.Fatalf("prepared clock missing: found=%v err=%v", found, err)
	}

	changed := proto.Clone(params).(*ProtocolParams)
	changed.Revision = 2
	changed.ValidatorHandoffNoticeSeconds = 7_200
	third := proto.Clone(changed.SettlementDomains[0]).(*SettlementDomain)
	third.Id = bytes.Repeat([]byte{0xb7}, 32)
	third.ChainId = 56
	changed.SettlementDomains = append(changed.SettlementDomains, third)
	store.put(t, KeyForProtocolParams(), changed)
	validator := new(Validator)
	if found, err := contract.read(KeyForValidator(secondAddress), validator); err != nil || !found {
		t.Fatalf("validator missing: found=%v err=%v", found, err)
	}
	validator.StakedAmount = 9_999
	store.put(t, KeyForValidator(secondAddress), validator)

	if response := contract.endBlock(epochEndRequestAt(11, 10_001, proposer)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("extended boundary response = %#v", response)
	}
	after := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), after); err != nil || !found {
		t.Fatalf("extended clock missing: found=%v err=%v", found, err)
	}
	if !bytes.Equal(after.ValidatorHandoffRosterHash, before.ValidatorHandoffRosterHash) ||
		!bytes.Equal(after.ValidatorHandoffDomainSetHash, before.ValidatorHandoffDomainSetHash) ||
		after.ValidatorHandoffTimestamp != before.ValidatorHandoffTimestamp ||
		after.ValidatorHandoffNoticeSeconds != before.ValidatorHandoffNoticeSeconds ||
		len(after.ValidatorHandoffDomains) != len(before.ValidatorHandoffDomains) {
		t.Fatalf("later state rewrote frozen transition: before=%#v after=%#v", before, after)
	}
}

func TestLegacyLeadHeightPreparedStateIsRejected(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEpochClock(), &EpochClock{
		CurrentEpoch: 1, StartHeight: 1, EndHeight: 10, ValidatorSetId: 1,
		EpochBlocks: 10, ValidatorHandoffPrepared: true,
	})
	if _, err := contract.currentEpochClock(params); err == nil || !strings.Contains(err.Msg, "boundary migration") {
		t.Fatalf("legacy prepared state was silently reinterpreted: %v", err)
	}
}

func TestAuthorityHandoffDomainsIgnoreTrafficActivationAcrossEpochs(t *testing.T) {
	params := defaultProtocolParams()
	staged := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	staged.Id = bytes.Repeat([]byte{0x95}, 32)
	staged.ChainId = 56
	staged.Active = false
	params.SettlementDomains = append(params.SettlementDomains, staged)
	first := authorityHandoffDomains(params)
	if len(first) != 2 || !slices.ContainsFunc(first, func(id []byte) bool { return bytes.Equal(id, staged.Id) }) {
		t.Fatalf("staged domain omitted from authority handoff: %x", first)
	}
	params.SettlementDomains[0].Active = false
	staged.Active = true
	second := authorityHandoffDomains(params)
	if len(second) != 2 || !slices.EqualFunc(first, second, bytes.Equal) {
		t.Fatalf("traffic activation rewrote later authority snapshot: first=%x second=%x", first, second)
	}
}

func TestGovernanceCannotRemoveDomainWithoutRetirementProtocol(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision = 1
	params.ValidatorSetId = 1
	params.ApprovedPcrs = []*PCRPolicy{testPCRPolicy()}
	second := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	second.ChainId = 56
	second.Network = "eip155:56"
	second.TokenAddress = bytes.Repeat([]byte{0x81}, 20)
	second.EscrowAddress = bytes.Repeat([]byte{0x82}, 20)
	second.VerifierAddress = bytes.Repeat([]byte{0x83}, 20)
	second.FoundationTreasuryAddress = bytes.Repeat([]byte{0x84}, 20)
	second.Id = keccak(abiUint64(second.ChainId), abiAddress(second.TokenAddress), abiAddress(second.EscrowAddress), abiAddress(second.VerifierAddress))
	params.SettlementDomains = append(params.SettlementDomains, second)
	store.put(t, KeyForProtocolParams(), params)

	deactivated := proto.Clone(params).(*ProtocolParams)
	deactivated.Revision = 2
	deactivated.SettlementDomains[1].Active = false
	encoded, err := Marshal(deactivated)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatalf("traffic deactivation incorrectly removed authority tracking: %v", response.Error)
	}
	preparedClock := &EpochClock{
		CurrentEpoch: 1, StartHeight: 1, EndHeight: params.EpochBlocks, ValidatorSetId: params.ValidatorSetId,
		EpochBlocks: params.EpochBlocks, ValidatorHandoffTimestamp: 100,
	}
	completePreparedClock(preparedClock, deactivated, nil)
	store.put(t, KeyForEpochClock(), preparedClock)
	reactivated := proto.Clone(deactivated).(*ProtocolParams)
	reactivated.Revision = 3
	reactivated.SettlementDomains[1].Active = true
	encoded, err = Marshal(reactivated)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error == nil {
		t.Fatal("staged domain was activated during a prepared validator handoff")
	}

	removed := proto.Clone(deactivated).(*ProtocolParams)
	removed.Revision = 3
	removed.SettlementDomains = removed.SettlementDomains[:1]
	encoded, err = Marshal(removed)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error == nil {
		t.Fatal("domain was removed without finalized pause, drain, and retirement protocol")
	}
	deactivation := new(ReplayMarker)
	if found, readErr := contract.read(KeyForSettlementDomainDeactivation(second.Id), deactivation); readErr != nil || !found {
		t.Fatalf("traffic deactivation marker missing: found=%v err=%v", found, readErr)
	} else if len(deactivation.Id) != 32 {
		t.Fatalf("deactivation generation length = %d", len(deactivation.Id))
	}
	deactivationEpoch := new(ReplayMarker)
	if found, readErr := contract.read(KeyForSettlementDomainDeactivationEpoch(second.Id), deactivationEpoch); readErr != nil || !found {
		t.Fatalf("traffic deactivation epoch missing: found=%v err=%v", found, readErr)
	} else if epoch, ok := settlementDomainDeactivationEpoch(deactivationEpoch); !ok || epoch != 1 {
		t.Fatalf("deactivation epoch = %d valid=%v", epoch, ok)
	}
	store.put(t, KeyForEpochClock(), &EpochClock{
		CurrentEpoch: 1, StartHeight: 1, EndHeight: params.EpochBlocks, ValidatorSetId: params.ValidatorSetId,
		EpochBlocks:                   params.EpochBlocks,
		ValidatorHandoffNoticeSeconds: params.ValidatorHandoffNoticeSeconds,
	})
	store.put(t, KeyForSettlementDomainRetirement(second.Id), &ReplayMarker{Id: bytes.Repeat([]byte{0xaa}, 32)})
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatalf("finalized retired domain removal failed: %v", response.Error)
	}
	readded := proto.Clone(removed).(*ProtocolParams)
	readded.Revision = 4
	readded.SettlementDomains = append(readded.SettlementDomains, second)
	encoded, err = Marshal(readded)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error == nil {
		t.Fatal("permanently retired domain identifier was re-admitted")
	}
}

func TestLifecycleIntentRequiresExactGovernedGenerationActionNonceAndExpiry(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 5
	domain := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	domain.Id = bytes.Repeat([]byte{0x97}, 32)
	domain.ChainId = 56
	domain.Network = "eip155:56"
	domain.Active = false
	params.SettlementDomains = append(params.SettlementDomains, domain)
	store.put(t, KeyForProtocolParams(), params)
	clock := &EpochClock{
		CurrentEpoch: 1, StartHeight: 1, EndHeight: params.EpochBlocks, ValidatorSetId: 5,
		EpochBlocks: params.EpochBlocks,
	}
	store.put(t, KeyForEpochClock(), clock)
	generation := bytes.Repeat([]byte{0x98}, 32)
	store.put(t, KeyForSettlementDomainDeactivation(domain.Id), &ReplayMarker{Id: generation})

	submit := func(intent *SettlementDomainLifecycleIntent) *PluginError {
		t.Helper()
		encoded, err := Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		return contract.deliverGovernedParameter(
			"takusen", "settlementDomainLifecycleIntent", []byte(base64.StdEncoding.EncodeToString(encoded)),
		).Error
	}
	intent := &SettlementDomainLifecycleIntent{
		SettlementDomainId: domain.Id, DeactivationGeneration: generation, Action: "retire", Nonce: 1, ExpiresAtEpoch: 2,
	}
	intent.Id = settlementDomainLifecycleIntentID(domain.Id, generation, intent.Action, intent.Nonce, intent.ExpiresAtEpoch)
	if err := submit(intent); err != nil {
		t.Fatalf("valid governed lifecycle intent failed: %v", err)
	}
	wrongAction := proto.Clone(intent).(*SettlementDomainLifecycleIntent)
	wrongAction.Action = "cancel"
	wrongAction.Id = settlementDomainLifecycleIntentID(domain.Id, generation, wrongAction.Action, wrongAction.Nonce, wrongAction.ExpiresAtEpoch)
	if err := submit(wrongAction); err == nil {
		t.Fatal("an unexpired governed lifecycle intent was replaced by a different action")
	}

	clock.CurrentEpoch = 3
	store.put(t, KeyForEpochClock(), clock)
	wrongGeneration := proto.Clone(intent).(*SettlementDomainLifecycleIntent)
	wrongGeneration.DeactivationGeneration = bytes.Repeat([]byte{0x99}, 32)
	wrongGeneration.Action, wrongGeneration.Nonce, wrongGeneration.ExpiresAtEpoch = "cancel", 2, 4
	wrongGeneration.Id = settlementDomainLifecycleIntentID(domain.Id, wrongGeneration.DeactivationGeneration, wrongGeneration.Action, 2, 4)
	if err := submit(wrongGeneration); err == nil {
		t.Fatal("lifecycle intent for a different deactivation generation was accepted")
	}
	replacement := proto.Clone(wrongGeneration).(*SettlementDomainLifecycleIntent)
	replacement.DeactivationGeneration = generation
	replacement.Id = settlementDomainLifecycleIntentID(domain.Id, generation, replacement.Action, replacement.Nonce, replacement.ExpiresAtEpoch)
	if err := submit(replacement); err != nil {
		t.Fatalf("expired intent could not be replaced with the next exact nonce: %v", err)
	}
	stored := new(SettlementDomainLifecycleIntent)
	if found, err := contract.read(KeyForSettlementDomainLifecycleIntent(domain.Id), stored); err != nil || !found ||
		!bytes.Equal(stored.Id, replacement.Id) {
		t.Fatalf("replacement lifecycle intent was not committed: found=%v err=%v", found, err)
	}
}

func TestGovernanceRequiresFinalizedAuthorityCertificateForDomainAdmissionAndActivation(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision = 1
	params.ValidatorSetId = 1
	params.ApprovedPcrs = []*PCRPolicy{testPCRPolicy()}
	store.put(t, KeyForProtocolParams(), params)

	staged := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	staged.ChainId = 56
	staged.Network = "eip155:56"
	staged.TokenAddress = bytes.Repeat([]byte{0x91}, 20)
	staged.EscrowAddress = bytes.Repeat([]byte{0x92}, 20)
	staged.VerifierAddress = bytes.Repeat([]byte{0x93}, 20)
	staged.FoundationTreasuryAddress = bytes.Repeat([]byte{0x94}, 20)
	staged.Id = keccak(abiUint64(staged.ChainId), abiAddress(staged.TokenAddress), abiAddress(staged.EscrowAddress), abiAddress(staged.VerifierAddress))
	staged.Active = false
	admitted := proto.Clone(params).(*ProtocolParams)
	admitted.Revision = 2
	admitted.SettlementDomains = append(admitted.SettlementDomains, staged)
	encoded, err := Marshal(admitted)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error == nil {
		t.Fatal("domain admission succeeded without finalized authority certificate")
	}
	store.put(t, KeyForSettlementDomainAuthority(staged.Id, params.ValidatorSetId), &ReplayMarker{Id: bytes.Repeat([]byte{0x95}, 32)})
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatalf("certified staged domain admission failed: %v", response.Error)
	}
	if found, readErr := contract.read(KeyForSettlementDomainDeactivation(staged.Id), new(ReplayMarker)); readErr != nil || found {
		t.Fatalf("initially staged domain acquired a false deactivation record: found=%v err=%v", found, readErr)
	}

	delete(store.values, string(KeyForSettlementDomainAuthority(staged.Id, params.ValidatorSetId)))
	activated := proto.Clone(admitted).(*ProtocolParams)
	activated.Revision = 3
	activated.SettlementDomains[1].Active = true
	encoded, err = Marshal(activated)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error == nil {
		t.Fatal("domain activation succeeded without a current finalized authority certificate")
	}
	store.put(t, KeyForSettlementDomainAuthority(staged.Id, params.ValidatorSetId), &ReplayMarker{Id: bytes.Repeat([]byte{0x96}, 32)})
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatalf("initial staged activation required a nonexistent retirement cancellation: %v", response.Error)
	}

	deactivated := proto.Clone(activated).(*ProtocolParams)
	deactivated.Revision = 4
	deactivated.SettlementDomains[1].Active = false
	encoded, err = Marshal(deactivated)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatalf("domain deactivation failed: %v", response.Error)
	}
	deactivation := new(ReplayMarker)
	if found, readErr := contract.read(KeyForSettlementDomainDeactivation(staged.Id), deactivation); readErr != nil || !found || len(deactivation.Id) != 32 {
		t.Fatalf("domain deactivation generation missing: found=%v err=%v", found, readErr)
	}
	reactivated := proto.Clone(deactivated).(*ProtocolParams)
	reactivated.Revision = 5
	reactivated.SettlementDomains[1].Active = true
	encoded, err = Marshal(reactivated)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error == nil {
		t.Fatal("domain reactivation succeeded without finalized retirement-proof cancellation")
	}
	store.put(t, KeyForSettlementDomainRetirementCancellation(staged.Id, deactivation.Id), &ReplayMarker{Id: bytes.Repeat([]byte{0x97}, 32)})
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatalf("certified domain reactivation failed: %v", response.Error)
	}
	if _, found := store.values[string(KeyForSettlementDomainRetirementCancellation(staged.Id, deactivation.Id))]; found {
		t.Fatal("consumed retirement cancellation marker was retained after activation")
	}
}

func TestGovernanceCanDiscardNeverActiveStagedDomain(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.ValidatorSetId = 1, 1
	params.ApprovedPcrs = []*PCRPolicy{testPCRPolicy()}
	store.put(t, KeyForProtocolParams(), params)

	staged := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	staged.ChainId, staged.Network, staged.Active = 42161, "eip155:42161", false
	staged.TokenAddress = bytes.Repeat([]byte{0xa1}, 20)
	staged.EscrowAddress = bytes.Repeat([]byte{0xa2}, 20)
	staged.VerifierAddress = bytes.Repeat([]byte{0xa3}, 20)
	staged.FoundationTreasuryAddress = bytes.Repeat([]byte{0xa4}, 20)
	staged.Id = keccak(abiUint64(staged.ChainId), abiAddress(staged.TokenAddress), abiAddress(staged.EscrowAddress), abiAddress(staged.VerifierAddress))
	store.put(t, KeyForSettlementDomainAuthority(staged.Id, params.ValidatorSetId), &ReplayMarker{Id: bytes.Repeat([]byte{0xa5}, 32)})

	admitted := proto.Clone(params).(*ProtocolParams)
	admitted.Revision = 2
	admitted.SettlementDomains = append(admitted.SettlementDomains, staged)
	encoded, err := Marshal(admitted)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatalf("staged admission failed: %v", response.Error)
	}

	discarded := proto.Clone(admitted).(*ProtocolParams)
	discarded.Revision = 3
	discarded.SettlementDomains = discarded.SettlementDomains[:1]
	encoded, err = Marshal(discarded)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error != nil {
		t.Fatalf("never-active staged domain discard failed: %v", response.Error)
	}
	if found, readErr := contract.read(KeyForSettlementDomainRetirement(staged.Id), new(ReplayMarker)); readErr != nil || !found {
		t.Fatalf("discarded staged domain was not tombstoned: found=%v err=%v", found, readErr)
	}

	readded := proto.Clone(discarded).(*ProtocolParams)
	readded.Revision = 4
	readded.SettlementDomains = append(readded.SettlementDomains, staged)
	encoded, err = Marshal(readded)
	if err != nil {
		t.Fatal(err)
	}
	if response := contract.deliverGovernedParameter("takusen", "protocolParams", []byte(base64.StdEncoding.EncodeToString(encoded))); response.Error == nil {
		t.Fatal("discarded staged domain identifier was re-admitted")
	}
}

func TestAbortRequiresFinalizedCancellationBeforeNewAttempt(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	params.ValidatorHandoffNoticeSeconds = 2_400
	store.put(t, KeyForProtocolParams(), params)
	if response := contract.endBlock(epochEndRequestAt(10, 10_000, proposer)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("boundary did not start first attempt: %#v", response)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.ValidatorHandoffAttempt != 1 || clock.ValidatorHandoffTimestamp != 12_400 {
		t.Fatalf("first attempt missing: found=%v err=%v clock=%#v", found, err, clock)
	}
	if response := contract.endBlock(epochEndRequestAt(11, 11_200, proposer)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("abort-window cancellation preparation failed: %#v", response)
	}
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.ValidatorHandoffAttempt != 1 || !clock.ValidatorHandoffCancelling {
		t.Fatalf("abort window did not preserve attempt one while cancellation finalizes: found=%v err=%v clock=%#v", found, err, clock)
	}
	if response := contract.endBlock(epochEndRequestAt(12, 12_400, proposer)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("unresolved cancellation wait failed: %#v", response)
	}
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.ValidatorHandoffAttempt != 1 {
		t.Fatalf("unresolved cancellation incorrectly created a new attempt: found=%v err=%v clock=%#v", found, err, clock)
	}
	// The EVM event itself proves cancellation finalized before T. Native may
	// certify that event later without turning a successful abort into a
	// permanent epoch extension.
	generation := validatorHandoffGeneration(clock)
	for _, domain := range clock.ValidatorHandoffDomains {
		proofID := hashFields([]byte("cancelled-rotation"), domain, uint64Bytes(clock.ValidatorSetId))
		store.put(t, KeyForQuorumProof(proofID), &QuorumProof{
			ProofKind: "validator-set-rotation-cancelled", ProofId: proofID,
			ValidatorSetId: clock.ValidatorSetId, NewValidatorSetId: clock.ValidatorSetId + 1,
			CompletedHeight: 12, SettlementDomainId: domain,
			HandoffGeneration: generation, HandoffTimestamp: clock.ValidatorHandoffTimestamp,
		})
		store.put(t, KeyForRotationResolutionIndex(domain, clock.ValidatorSetId, clock.ValidatorSetId+1), &ReplayMarker{Id: proofID})
	}
	if response := contract.endBlock(epochEndRequestAt(13, 12_500, proposer)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("late Native cancellation certification did not recover: %#v", response)
	}
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.ValidatorHandoffAttempt != 2 || clock.ValidatorHandoffCancelling {
		t.Fatalf("late cancellation did not start attempt two: found=%v err=%v clock=%#v", found, err, clock)
	}
}

func TestEpochBoundaryFailsClosedUntilRotationProofExists(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	params.CanonicalChainId = 8453
	store.put(t, KeyForProtocolParams(), params)

	response := contract.endBlock(epochEndRequest(10, proposer))
	if response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("unprepared boundary did not fail closed: %#v", response)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.EndHeight != 11 || clock.ValidatorSetId != 1 || !clock.ValidatorHandoffPrepared {
		t.Fatalf("extended epoch clock = %#v found=%v err=%v", clock, found, err)
	}
	seedQueuedRotation(t, store, params, 1)
	response = contract.endBlock(epochEndRequest(11, proposer))
	if response.Error != nil || !response.ValidatorSetEpochEnd {
		t.Fatalf("authorized boundary did not activate: %#v", response)
	}
}

func TestEpochBoundaryRequiresFinalizedScheduleForInactiveAuthorityDomain(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks, params.ValidatorSetId = 1, 10, 1
	second := proto.Clone(params.SettlementDomains[0]).(*SettlementDomain)
	second.Id = bytes.Repeat([]byte{0x92}, 32)
	second.ChainId = 56
	second.Active = false
	params.SettlementDomains = append(params.SettlementDomains, second)
	store.put(t, KeyForProtocolParams(), params)
	if response := contract.endBlock(epochEndRequest(10, proposer)); response.Error != nil || !response.ValidatorSetEpochPrepare {
		t.Fatalf("boundary handoff preparation = %#v", response)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found {
		t.Fatalf("prepared epoch clock missing: found=%v err=%v", found, err)
	}
	clock.ValidatorHandoffTimestamp = 1_300
	clock.ValidatorHandoffOutgoingAuthorityCutoff = 1_300
	store.put(t, KeyForEpochClock(), clock)
	generation := validatorHandoffGeneration(clock)

	first := params.SettlementDomains[0]
	proofID := hashFields([]byte("first-domain-only"))
	store.put(t, KeyForQuorumProof(proofID), &QuorumProof{
		ProofKind: "validator-set-rotation-queued", ProofId: proofID, ValidatorSetId: 1,
		NewValidatorSetId: 2, CompletedHeight: 9, SettlementDomainId: first.Id,
		HandoffGeneration: generation, HandoffTimestamp: clock.ValidatorHandoffTimestamp,
	})
	store.put(t, KeyForQueuedRotationIndex(first.Id, 1, 2), &ReplayMarker{Id: proofID})
	if response := contract.endBlock(epochEndRequest(11, proposer)); response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("one-domain handoff advanced a two-domain epoch: %#v", response)
	}

	secondProofID := hashFields([]byte("second-domain"))
	store.put(t, KeyForQuorumProof(secondProofID), &QuorumProof{
		ProofKind: "validator-set-rotation-queued", ProofId: secondProofID, ValidatorSetId: 1,
		NewValidatorSetId: 2, CompletedHeight: 10, SettlementDomainId: second.Id,
		HandoffGeneration: bytes.Repeat([]byte{0x43}, 32), HandoffTimestamp: clock.ValidatorHandoffTimestamp,
	})
	store.put(t, KeyForQueuedRotationIndex(second.Id, 1, 2), &ReplayMarker{Id: secondProofID})
	if response := contract.endBlock(epochEndRequest(12, proposer)); response.Error == nil || response.ValidatorSetEpochEnd {
		t.Fatalf("mismatched global handoff generations advanced: %#v", response)
	}
	store.put(t, KeyForQuorumProof(secondProofID), &QuorumProof{
		ProofKind: "validator-set-rotation-queued", ProofId: secondProofID, ValidatorSetId: 1,
		NewValidatorSetId: 2, CompletedHeight: 11, SettlementDomainId: second.Id,
		HandoffGeneration: generation, HandoffTimestamp: clock.ValidatorHandoffTimestamp,
	})
	if response := contract.endBlock(epochEndRequestAt(12, 1_300, proposer)); response.Error != nil || !response.ValidatorSetEpochEnd {
		t.Fatalf("all-domain handoff did not advance: %#v", response)
	}
}

func TestEpochProcessesPendingSlashesInBoundedChunks(t *testing.T) {
	contract, store, proposer, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks = 1, 10
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForServicer(proposer), &Servicer{OwnerAddress: proposer, Bond: 1_000, Active: true})
	for index := uint64(0); index < maxEpochSlashApplications+1; index++ {
		evidenceID := hashFields([]byte("bounded-slash"), uint64Bytes(index))
		store.put(t, KeyForSlashEvidence(evidenceID), &SlashEvidence{
			EvidenceId: evidenceID, TargetAddress: proposer, Penalty: 1,
			EffectiveEpoch: 1, Status: "queued",
		})
		store.put(t, KeyForPendingSlash(1, evidenceID), &ReplayMarker{Id: evidenceID})
	}
	response := contract.endBlock(epochEndRequestWithWeights(10, 10, proposer, 100, 100))
	if response.Error != nil || response.ValidatorSetEpochEnd {
		t.Fatalf("first bounded slash chunk = %#v", response)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found || clock.EndHeight != 11 || clock.CurrentEpoch != 1 {
		t.Fatalf("extended slash epoch = %#v found=%v err=%v", clock, found, err)
	}
	pending, err := contract.rangeRead(PendingSlashPrefix())
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending slash remainder=%d err=%v", len(pending), err)
	}
	response = contract.endBlock(epochEndRequestWithWeights(11, 11, proposer, 100, 100))
	if response.Error != nil || !response.ValidatorSetEpochEnd {
		t.Fatalf("final bounded slash chunk = %#v", response)
	}
	pending, err = contract.rangeRead(PendingSlashPrefix())
	if err != nil || len(pending) != 0 {
		t.Fatalf("pending slash queue not drained: entries=%d err=%v", len(pending), err)
	}
}

func TestEpochClockMigratesFromExistingAuthorizations(t *testing.T) {
	contract, store, first, _ := newMemoryContract(t)
	params := defaultProtocolParams()
	params.Revision, params.EpochBlocks = 8, 13_091
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForEpochAuthorization(164), &EpochAuthorization{Epoch: 164, StartHeight: 16_301, EndHeight: 16_400})
	store.put(t, KeyForLatestEpoch(), &ReplayMarker{Id: uint64Bytes(164)})

	if response := contract.endBlock(epochEndRequest(17_000, first)); response.Error != nil {
		t.Fatal(response.Error)
	}
	clock := new(EpochClock)
	if found, err := contract.read(KeyForEpochClock(), clock); err != nil || !found {
		t.Fatalf("migrated epoch clock missing: found=%v err=%v", found, err)
	}
	if clock.CurrentEpoch != 165 || clock.StartHeight != 16_401 || clock.EndHeight != 29_491 {
		t.Fatalf("migrated epoch clock = %#v", clock)
	}
}

func signedExecution(t *testing.T, privateKey ed25519.PrivateKey, publicKey []byte, keyID string, owner []byte, requestID, executionID string, inputHash [32]byte) *MessageSubmitExecution {
	t.Helper()
	outputHash := sha256.Sum256([]byte("true"))
	commitment := "0x" + hex.EncodeToString(outputHash[:])
	archiveID := "sha256:" + strings.Repeat("ab", 32)
	receipt := receipt{
		Domain:      "takusen:execution-receipt",
		ExecutionID: executionID, RequestID: requestID, InputHash: "0x" + hex.EncodeToString(inputHash[:]),
		SettlementDomain: "0x" + hex.EncodeToString(testSettlementDomainID()),
		Model:            "model", Provider: "provider", Status: "success", Output: "true", OutputHash: commitment,
		PromptTokens: 1, CompletionTokens: 1, CostMicros: 10, MaxProviderCostMicros: 100,
		ProviderRequestHash: commitment, ProviderResponseHash: commitment, ArchiveID: archiveID, ExecutionNonce: commitment,
		TEEKeyID: keyID, StartedAtMS: 1, CompletedAtMS: 2,
	}
	canonical := canonicalTestReceipt(receipt)
	digest := sha256.Sum256(canonical)
	return &MessageSubmitExecution{
		ServicerAddress: owner, ReceiptJson: canonical, PublicKey: publicKey,
		Signature: ed25519.Sign(privateKey, digest[:]), ArchiveId: archiveID,
	}
}

func canonicalTestReceipt(receipt receipt) []byte {
	canonical, _ := json.Marshal([]any{
		receipt.Domain,
		receipt.ExecutionID, receipt.RequestID, receipt.InputHash, receipt.SettlementDomain, receipt.Model, receipt.Provider, receipt.Status, receipt.Output, receipt.OutputHash,
		strconv.FormatInt(receipt.PromptTokens, 10), strconv.FormatInt(receipt.CompletionTokens, 10), strconv.FormatInt(receipt.CostMicros, 10),
		strconv.FormatInt(receipt.MaxProviderCostMicros, 10), receipt.ProviderRequestHash, receipt.ProviderResponseHash, receipt.ArchiveID, receipt.ExecutionNonce, receipt.TEEKeyID,
		strconv.FormatInt(receipt.StartedAtMS, 10), strconv.FormatInt(receipt.CompletedAtMS, 10),
	})
	return canonical
}

func TestZeroCostEnclaveReceiptQueuesSlashAndLeavesAssignmentRetryable(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	owner := bytes.Repeat([]byte{7}, 20)
	keyDigest := sha256.Sum256(publicKey)
	keyID := "ed25519:" + hex.EncodeToString(keyDigest[:])
	inputHash := sha256.Sum256([]byte("input"))
	params := defaultProtocolParams()
	params.Revision, params.InvalidReceiptSlashBps = 1, 5_000
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForRequest("request"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "request", Requester: owner, InputHash: inputHash[:], OutputType: "boolean",
		Models: []string{"model"}, ExecutionQuorum: 1, Status: "authorized", DeadlineHeight: 100,
		Assignments: []*Assignment{{Model: "model", Provider: "provider", ServicerAddress: owner, DeadlineHeight: 100, ExecutionId: assignmentExecutionID("request", "model", 0, owner, inputHash[:]), TeeKeyId: keyID, MaxProviderCost: 100}},
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), "request"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: "request", Requester: owner, Budget: 100, Status: "reserved"})
	store.put(t, KeyForServicer(owner), &Servicer{
		OwnerAddress: owner, TeeKeyId: keyID, Models: []string{"model"}, Bond: 100, Active: true,
	})
	store.put(t, KeyForEnclave(keyID), &EnclaveKey{
		OwnerAddress: owner, TeeKeyId: keyID, PublicKey: publicKey, Active: true,
	})

	executionID := assignmentExecutionID("request", "model", 0, owner, inputHash[:])
	message := signedExecution(t, privateKey, publicKey, keyID, owner, "request", executionID, inputHash)
	parsed, parseErr := parseCanonicalReceipt(message.ReceiptJson)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	parsed.CostMicros = 0
	canonical := canonicalTestReceipt(*parsed)
	digest := sha256.Sum256(canonical)
	message.ReceiptJson = canonical
	message.Signature = ed25519.Sign(privateKey, digest[:])

	if response := contract.deliverSubmitExecution(50, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	if found, readErr := contract.read(KeyForExecution(executionID), new(ExecutionRecord)); readErr != nil || found {
		t.Fatalf("invalid receipt became an execution: found=%v err=%v", found, readErr)
	}
	request := new(RequestRecord)
	if found, readErr := contract.read(KeyForRequest("request"), request); readErr != nil || !found || request.Assignments[0].Completed {
		t.Fatalf("invalid receipt completed its assignment: found=%v err=%v request=%#v", found, readErr, request)
	}
	servicer := new(Servicer)
	if found, readErr := contract.read(KeyForServicer(owner), servicer); readErr != nil || !found || servicer.FailureCount != 1 {
		t.Fatalf("servicer failure was not recorded: found=%v err=%v servicer=%#v", found, readErr, servicer)
	}
	evidenceID := hashFields([]byte("takusen:invalid-receipt"), digest[:])
	evidence := new(SlashEvidence)
	if found, readErr := contract.read(KeyForSlashEvidence(evidenceID), evidence); readErr != nil || !found || evidence.Reason != "invalid_receipt" || evidence.Penalty != 50 || evidence.Status != "queued" {
		t.Fatalf("invalid receipt slash was not queued: found=%v err=%v evidence=%#v", found, readErr, evidence)
	}
	records := make(map[string]proto.Message)
	deletes, _, applyErr := contract.applyEpochSlashes(2, params, records, 100)
	if applyErr != nil {
		t.Fatal(applyErr)
	}
	if writeErr := contract.writeChanges(records, deletes); writeErr != nil {
		t.Fatal(writeErr)
	}
	if found, readErr := contract.read(KeyForServicer(owner), servicer); readErr != nil || !found || servicer.Bond != 50 {
		t.Fatalf("automatic invalid-receipt slash was not applied at the next epoch: found=%v servicer=%#v err=%v", found, servicer, readErr)
	}
}

func TestAssignmentProviderCostLimitIsConsensusAuthenticated(t *testing.T) {
	tests := []struct {
		name     string
		cost     int64
		limit    int64
		status   string
		output   string
		accepted bool
	}{
		{name: "success at limit", cost: 100, limit: 100, status: "success", output: "true", accepted: true},
		{name: "host lowers limit", cost: 10, limit: 1, status: "budget_exhausted", accepted: false},
		{name: "budget exhausted below limit", cost: 99, limit: 100, status: "budget_exhausted", accepted: false},
		{name: "success above limit", cost: 101, limit: 100, status: "success", output: "true", accepted: false},
		{name: "budget exhausted above limit", cost: 101, limit: 100, status: "budget_exhausted", accepted: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contract, store, _, _ := newMemoryContract(t)
			publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			owner := bytes.Repeat([]byte{7}, 20)
			keyDigest := sha256.Sum256(publicKey)
			keyID := "ed25519:" + hex.EncodeToString(keyDigest[:])
			inputHash := sha256.Sum256([]byte("cost-limit-input"))
			executionID := assignmentExecutionID("request", "model", 0, owner, inputHash[:])
			store.put(t, KeyForProtocolParams(), func() *ProtocolParams { p := defaultProtocolParams(); p.Revision = 1; return p }())
			store.put(t, KeyForRequest("request"), &RequestRecord{
				SettlementDomainId: testSettlementDomainID(), RequestId: "request", Requester: owner, InputHash: inputHash[:],
				OutputType: "boolean", Models: []string{"model"}, ExecutionQuorum: 1, Status: "authorized", DeadlineHeight: 100,
				Assignments: []*Assignment{{Model: "model", Provider: "provider", ServicerAddress: owner, DeadlineHeight: 100, ExecutionId: executionID, TeeKeyId: keyID, MaxProviderCost: 100}},
			})
			store.put(t, KeyForReservation(testSettlementDomainID(), "request"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: "request", Requester: owner, Budget: 100, Status: "reserved"})
			store.put(t, KeyForServicer(owner), &Servicer{OwnerAddress: owner, TeeKeyId: keyID, Models: []string{"model"}, Bond: 100, Active: true})
			store.put(t, KeyForEnclave(keyID), &EnclaveKey{OwnerAddress: owner, TeeKeyId: keyID, PublicKey: publicKey, Active: true})

			message := signedExecution(t, privateKey, publicKey, keyID, owner, "request", executionID, inputHash)
			parsed, parseErr := parseCanonicalReceipt(message.ReceiptJson)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			parsed.CostMicros, parsed.MaxProviderCostMicros, parsed.Status, parsed.Output = test.cost, test.limit, test.status, test.output
			outputHash := sha256.Sum256([]byte(test.output))
			parsed.OutputHash = "0x" + hex.EncodeToString(outputHash[:])
			message.ReceiptJson = canonicalTestReceipt(*parsed)
			digest := sha256.Sum256(message.ReceiptJson)
			message.Signature = ed25519.Sign(privateKey, digest[:])
			if response := contract.deliverSubmitExecution(50, message); response.Error != nil {
				t.Fatal(response.Error)
			}
			_, found := store.values[string(KeyForExecution(executionID))]
			if found != test.accepted {
				t.Fatalf("execution accepted=%v, want %v", found, test.accepted)
			}
		})
	}
}

func TestFinalReceiptMakesRequestReadyOnlyAfterAllAssignmentsResolve(t *testing.T) {
	contract, store, _, _ := newMemoryContract(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	owner := bytes.Repeat([]byte{8}, 20)
	requester := bytes.Repeat([]byte{9}, 20)
	keyDigest := sha256.Sum256(publicKey)
	keyID := "ed25519:" + hex.EncodeToString(keyDigest[:])
	inputHash := sha256.Sum256([]byte("late-input"))
	outputHash := sha256.Sum256([]byte("true"))
	params := defaultProtocolParams()
	params.Revision = 1
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForRequest("late"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "late", Requester: requester, InputHash: inputHash[:],
		OutputType: "boolean", Models: []string{"prior", "model"}, ExecutionQuorum: 1, Status: "authorized", DeadlineHeight: 100,
		Assignments: []*Assignment{
			{Model: "prior", Completed: true, ExecutionId: "prior-execution"},
			{Model: "model", Provider: "provider", ServicerAddress: owner, DeadlineHeight: 100, ExecutionId: assignmentExecutionID("late", "model", 0, owner, inputHash[:]), TeeKeyId: keyID, MaxProviderCost: 100},
		},
	})
	store.put(t, KeyForExecution("prior-execution"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(),
		ExecutionId: "prior-execution", RequestId: "late", Model: "prior", Status: "success", Output: "true", OutputHash: outputHash[:],
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), "late"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: "late", Requester: requester, Budget: 200, Spent: 10, Status: "reserved"})
	store.put(t, KeyForServicer(owner), &Servicer{OwnerAddress: owner, TeeKeyId: keyID, Models: []string{"model"}, Bond: 100, Active: true})
	store.put(t, KeyForEnclave(keyID), &EnclaveKey{OwnerAddress: owner, TeeKeyId: keyID, PublicKey: publicKey, Active: true})

	executionID := assignmentExecutionID("late", "model", 0, owner, inputHash[:])
	if response := contract.deliverSubmitExecution(50, signedExecution(t, privateKey, publicKey, keyID, owner, "late", executionID, inputHash)); response.Error != nil {
		t.Fatal(response.Error)
	}
	request := new(RequestRecord)
	reservation := new(ReservationRecord)
	reservationFound, reservationErr := contract.read(KeyForReservation(testSettlementDomainID(), "late"), reservation)
	if found, readErr := contract.read(KeyForRequest("late"), request); readErr != nil || !found || request.Status != "ready" ||
		!request.Assignments[1].Completed || !reservationFound || reservationErr != nil || reservation.Spent <= 10 || request.AgreementCount != 2 {
		t.Fatalf("late execution was not charged into consensus: found=%v err=%v request=%#v reservation=%#v reservationErr=%v", found, readErr, request, reservation, reservationErr)
	}
}

func TestTimeoutExhaustionBecomesReady(t *testing.T) {
	contract, store, first, second := newMemoryContract(t)
	servicerAddress := bytes.Repeat([]byte{10}, 20)
	params := defaultProtocolParams()
	params.Revision, params.TimeoutSlashBps, params.RetryLimit = 1, 1_000, 0
	store.put(t, KeyForProtocolParams(), params)
	store.put(t, KeyForServicer(servicerAddress), &Servicer{OwnerAddress: servicerAddress, Models: []string{"model"}, Bond: 100, Active: true})
	store.put(t, KeyForRequest("resolved"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "resolved", InputHash: bytes.Repeat([]byte{11}, 32), Models: []string{"prior", "model"}, Status: "authorized", DeadlineHeight: 10,
		Assignments: []*Assignment{
			{Model: "prior", Completed: true, ExecutionId: "prior-execution"},
			{Model: "model", ServicerAddress: servicerAddress, ExecutionId: "expired-execution", DeadlineHeight: 10},
		},
	})
	store.put(t, KeyForExecution("prior-execution"), &ExecutionRecord{SettlementDomainId: testSettlementDomainID(), ExecutionId: "prior-execution", RequestId: "resolved", Model: "prior", Status: "success", Output: "true", OutputHash: bytes.Repeat([]byte{12}, 32)})
	message := &MessageReassignRequest{ObserverAddress: first, RequestId: "resolved", Model: "model", NewDeadlineHeight: 50}
	if response := contract.deliverReassignRequest(20, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	message.ObserverAddress = second
	if response := contract.deliverReassignRequest(21, message); response.Error != nil {
		t.Fatal(response.Error)
	}
	request := new(RequestRecord)
	if found, err := contract.read(KeyForRequest("resolved"), request); err != nil || !found || request.Status != "ready" ||
		!request.Assignments[1].Completed || request.Assignments[1].ExecutionId != "expired-execution" || request.Assignments[1].TerminalStatus != "failed" {
		t.Fatalf("timed-out post-quorum assignment was not terminally resolved: found=%v err=%v request=%#v", found, err, request)
	}
}

func TestFinalizeRejectsUnresolvedAssignments(t *testing.T) {
	contract, store, first, _ := newMemoryContract(t)
	store.put(t, KeyForRequest("unresolved"), &RequestRecord{SettlementDomainId: testSettlementDomainID(),
		RequestId: "unresolved", Requester: bytes.Repeat([]byte{12}, 20), Status: "authorized",
		Assignments: []*Assignment{{Model: "model"}},
	})
	store.put(t, KeyForReservation(testSettlementDomainID(), "unresolved"), &ReservationRecord{SettlementDomainId: testSettlementDomainID(), RequestId: "unresolved", Requester: bytes.Repeat([]byte{12}, 20), Budget: 100, Spent: 10, Status: "reserved"})
	response := contract.deliverFinalizeRequest(30, &MessageFinalizeRequest{SettlementDomainId: testSettlementDomainID(),
		ObserverAddress: first, RequestId: "unresolved", SettlementTxHash: bytes.Repeat([]byte{13}, 32), ReservedBudget: 100,
	})
	if response.Error == nil {
		t.Fatal("settlement finalized while model work was still unresolved")
	}
}
