package contract

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
)

const (
	rpcPageSize             = 500
	rpcUnauthenticatedLimit = 600
	rpcAuthenticatedLimit   = 60_000
	rpcRateWindow           = time.Minute
	rpcStreamLifetime       = 30 * time.Second
)

func (p *Plugin) StartRPCServer(ctx context.Context) {
	addr := p.config.RPCAddress
	if addr == "" {
		log.Println("Takusen plugin RPC server disabled")
		return
	}
	if !loopbackListenAddress(addr) && p.config.RPCAuthToken == "" {
		log.Printf("Takusen plugin RPC refused non-loopback listen address %s without TAKUSEN_PLUGIN_RPC_TOKEN", addr)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "module": "takusen", "build": PluginBuild})
	})
	mux.HandleFunc("GET /v1/takusen/events", p.eventStreamHandler())
	mux.HandleFunc("GET /v1/takusen/requests/{id}", p.recordHandler(func(id string) []byte { return KeyForRequest(id) }, func() proto.Message { return new(RequestRecord) }))
	mux.HandleFunc("GET /v1/takusen/executions/{id}", p.recordHandler(func(id string) []byte { return KeyForExecution(id) }, func() proto.Message { return new(ExecutionRecord) }))
	mux.HandleFunc("GET /v1/takusen/enclaves/{id}", p.recordHandler(func(id string) []byte { return KeyForEnclave(id) }, func() proto.Message { return new(EnclaveKey) }))
	mux.HandleFunc("GET /v1/takusen/domains/{domain}/deposits/{id}", p.domainHexRecordHandler(32, KeyForDeposit, func() proto.Message { return new(DepositRecord) }))
	mux.HandleFunc("GET /v1/takusen/domains/{domain}/credits/{id}", p.domainHexRecordHandler(20, KeyForCredit, func() proto.Message { return new(CreditAccount) }))
	mux.HandleFunc("GET /v1/takusen/domains/{domain}/reservations/{id}", p.domainRecordHandler(KeyForReservation, func() proto.Message { return new(ReservationRecord) }))
	mux.HandleFunc("GET /v1/takusen/domains/{domain}/deactivation", p.domainMarkerHandler(KeyForSettlementDomainDeactivation))
	mux.HandleFunc("GET /v1/takusen/domains/{domain}/deactivation-epoch", p.domainMarkerHandler(KeyForSettlementDomainDeactivationEpoch))
	mux.HandleFunc("GET /v1/takusen/domains/{domain}/retirement", p.domainMarkerHandler(KeyForSettlementDomainRetirement))
	mux.HandleFunc("GET /v1/takusen/domains/{domain}/lifecycle-intent", p.domainRecordValueHandler(KeyForSettlementDomainLifecycleIntent, func() proto.Message { return new(SettlementDomainLifecycleIntent) }))
	mux.HandleFunc("GET /v1/takusen/params", p.singletonHandler(KeyForProtocolParams(), func() proto.Message { return new(ProtocolParams) }))
	mux.HandleFunc("GET /v1/takusen/epoch-clock", p.singletonHandler(KeyForEpochClock(), func() proto.Message { return new(EpochClock) }))
	mux.HandleFunc("GET /v1/takusen/validators/next", p.nextValidatorSetHandler())
	mux.HandleFunc("GET /v1/takusen/validator-rotations/{old}/{new}/queues-ready", p.rotationQueuesReadyHandler())
	mux.HandleFunc("GET /v1/takusen/validator-handoffs/current/{domain}", p.validatorHandoffManifestHandler(false))
	mux.HandleFunc("GET /v1/takusen/validator-handoffs/cancellation/{domain}", p.validatorHandoffManifestHandler(true))
	mux.HandleFunc("GET /v1/takusen/stake-changes/{id}", p.hexRecordHandler(20, KeyForStakeChange, func() proto.Message { return new(StakeChange) }))
	mux.HandleFunc("GET /v1/takusen/slashes/{id}", p.hexRecordHandler(32, KeyForSlashEvidence, func() proto.Message { return new(SlashEvidence) }))
	mux.HandleFunc("GET /v1/takusen/producer-payouts/{id}", p.hexRecordHandler(20, KeyForProducerPayout, func() proto.Message { return new(ProducerPayout) }))
	mux.HandleFunc("GET /v1/takusen/epochs/{id}", p.uintRecordHandler(KeyForEpochAuthorization, func() proto.Message { return new(EpochAuthorization) }))
	mux.HandleFunc("GET /v1/takusen/epochs/pending", p.listHandler(PendingEpochAuthorizationPrefix(), func() proto.Message { return new(ReplayMarker) }))
	mux.HandleFunc("GET /v1/takusen/bridge/mints/{id}", p.hexRecordHandler(32, KeyForBridgeMint, func() proto.Message { return new(BridgeMint) }))
	mux.HandleFunc("GET /v1/takusen/bridge/burns/{id}", p.hexRecordHandler(32, KeyForBridgeBurn, func() proto.Message { return new(BridgeBurn) }))
	mux.HandleFunc("GET /v1/takusen/bridge/burns/pending", p.listHandler(PendingBridgeBurnPrefix(), func() proto.Message { return new(ReplayMarker) }))
	mux.HandleFunc("GET /v1/takusen/servicers", p.listHandler(ServicerPrefix(), func() proto.Message { return new(Servicer) }))
	mux.HandleFunc("GET /v1/takusen/requests", p.listHandler(RequestPrefix(), func() proto.Message { return new(RequestRecord) }))
	mux.HandleFunc("GET /v1/takusen/authorizations/pending", p.listHandler(PendingAuthorizationPrefix(), func() proto.Message { return new(PendingAuthorization) }))
	mux.HandleFunc("GET /v1/takusen/assignments/{id}", p.assignmentListHandler())
	mux.HandleFunc("GET /v1/takusen/settlement-requests", p.settlementRequestListHandler())
	mux.HandleFunc("GET /v1/takusen/settlement-bundle", p.settlementBundleHandler())
	mux.HandleFunc("POST /v1/takusen/settlement-bundle", p.settlementBundleHandler())
	mux.HandleFunc("GET /v1/takusen/deposits", p.listHandler(DepositPrefix(), func() proto.Message { return new(DepositRecord) }))
	mux.HandleFunc("GET /v1/takusen/credits", p.listHandler(CreditPrefix(), func() proto.Message { return new(CreditAccount) }))
	mux.HandleFunc("GET /v1/takusen/reservations", p.listHandler(ReservationPrefix(), func() proto.Message { return new(ReservationRecord) }))
	mux.HandleFunc("GET /v1/takusen/stake-changes", p.listHandler(StakeChangePrefix(), func() proto.Message { return new(StakeChange) }))
	mux.HandleFunc("GET /v1/takusen/unbondings", p.listHandler(UnbondingPrefix(), func() proto.Message { return new(UnbondingRecord) }))
	mux.HandleFunc("GET /v1/takusen/slashes", p.listHandler(SlashEvidencePrefix(), func() proto.Message { return new(SlashEvidence) }))
	mux.HandleFunc("GET /v1/takusen/producer-payouts", p.listHandler(ProducerPayoutPrefix(), func() proto.Message { return new(ProducerPayout) }))
	mux.HandleFunc("GET /v1/takusen/epochs", p.listHandler(EpochAuthorizationPrefix(), func() proto.Message { return new(EpochAuthorization) }))
	mux.HandleFunc("GET /v1/takusen/bridge/mints", p.listHandler(BridgeMintPrefix(), func() proto.Message { return new(BridgeMint) }))
	mux.HandleFunc("GET /v1/takusen/bridge/burns", p.listHandler(BridgeBurnPrefix(), func() proto.Message { return new(BridgeBurn) }))
	mux.HandleFunc("GET /v1/takusen/quorum-proofs/{id}", p.quorumProofHandler())
	mux.HandleFunc("GET /v1/takusen/quorum-proofs/rotation/{domain}/{old}/{new}", p.rotationProofHandler())
	mux.HandleFunc("GET /v1/takusen/quorum-proofs/authority/{domain}/{set}", p.settlementDomainAuthorityProofHandler())
	mux.HandleFunc("GET /v1/takusen/quorum-proofs", p.listHandler(QuorumProofPrefix(), func() proto.Message { return new(QuorumProof) }))
	mux.HandleFunc("GET /v1/takusen/consensus-certificates", p.listHandler(ConsensusCertificatePrefix(), func() proto.Message { return new(ConsensusCertificate) }))
	mux.HandleFunc("GET /v1/takusen/consensus-certificates/{kind}/{key}", p.latestConsensusCertificateHandler())
	mux.HandleFunc("GET /v1/takusen/consensus-certificates/{kind}/{key}/{digest}", p.consensusCertificateHandler())
	mux.HandleFunc("GET /v1/takusen/native-authorization-intents/{kind}/{domain}", p.nativeAuthorizationIntentHandler())
	handler := p.secureRPCHandler(mux)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("Takusen plugin RPC listen error: %v", err)
		return
	}
	listener = newLimitedListener(listener, p.config.RPCMaxConnections)
	server := &http.Server{
		Addr: addr, Handler: handler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 35 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("Takusen plugin RPC server (%s) listening on %s", PluginBuild, addr)
	if err = server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Printf("Takusen plugin RPC server error: %v", err)
	}
}

func (p *Plugin) nativeAuthorizationIntentHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind := r.PathValue("kind")
		domain, err := decodePathHex(r.PathValue("domain"), 32)
		if (kind != "settlement-domain-retirement-readiness" && kind != "settlement-domain-retirement-cancellation-readiness") || err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid native authorization intent"})
			return
		}
		p.recordHandler(func(string) []byte { return KeyForNativeAuthorizationIntent(kind, domain) }, func() proto.Message { return new(QuorumProof) })(w, r)
	}
}

func (p *Plugin) latestConsensusCertificateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind := r.PathValue("kind")
		key, keyErr := hex.DecodeString(strings.TrimPrefix(r.PathValue("key"), "0x"))
		if kind == "" || len(kind) > 64 || keyErr != nil || len(key) == 0 || len(key) > 128 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid consensus certificate identity"})
			return
		}
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		entries, err := p.rpcRangePage(w, r, height, ConsensusCertificateIdentityPrefix(kind, key))
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		var latest *ConsensusCertificate
		for _, entry := range entries {
			candidate := new(ConsensusCertificate)
			if decodeErr := Unmarshal(entry.Value, candidate); decodeErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
				return
			}
			if latest == nil || candidate.CompletedHeight > latest.CompletedHeight {
				latest = candidate
			}
		}
		if latest == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "consensus certificate not found"})
			return
		}
		writeJSON(w, http.StatusOK, latest)
	}
}

func (p *Plugin) consensusCertificateHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		kind := r.PathValue("kind")
		key, keyErr := hex.DecodeString(strings.TrimPrefix(r.PathValue("key"), "0x"))
		digest, digestErr := decodePathHex(r.PathValue("digest"), 32)
		if kind == "" || len(kind) > 64 || keyErr != nil || len(key) == 0 || len(key) > 128 || digestErr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid consensus certificate identity"})
			return
		}
		p.recordHandler(func(string) []byte { return KeyForConsensusCertificate(kind, key, digest) }, func() proto.Message { return new(ConsensusCertificate) })(w, r)
	}
}

func (p *Plugin) validatorHandoffManifestHandler(cancellation bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domainID, err := decodePathHex(r.PathValue("domain"), 32)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "settlement domain must be 32-byte hexadecimal"})
			return
		}
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		key := KeyForValidatorHandoffManifest()
		if cancellation {
			key = KeyForValidatorHandoffCancellationManifest()
		}
		state, queryErr := p.QueryState(height, &PluginStateReadRequest{Keys: []*PluginKeyRead{{QueryId: 1, Key: key}}})
		if queryErr != nil || len(state.Results) != 1 || len(state.Results[0].Entries) != 1 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "validator handoff manifest is unavailable"})
			return
		}
		if cancellation {
			manifest := new(ValidatorHandoffCancellationManifest)
			if Unmarshal(state.Results[0].Entries[0].Value, manifest) != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "validator cancellation manifest is invalid"})
				return
			}
			leaves := make([][]byte, len(manifest.Domains))
			position := -1
			for index, domain := range manifest.Domains {
				leaves[index] = domain.LeafHash
				if bytes.Equal(domain.SettlementDomainId, domainID) {
					position = index
				}
			}
			if position < 0 {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "settlement domain is absent from the cancellation manifest"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"manifest": manifest, "domain": manifest.Domains[position], "leaf_index": position, "merkle_proof": handoffMerkleProof(leaves, position)})
			return
		}
		manifest := new(ValidatorHandoffManifest)
		if Unmarshal(state.Results[0].Entries[0].Value, manifest) != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "validator handoff manifest is invalid"})
			return
		}
		leaves := make([][]byte, len(manifest.Domains))
		position := -1
		for index, domain := range manifest.Domains {
			leaves[index] = domain.LeafHash
			if bytes.Equal(domain.SettlementDomainId, domainID) {
				position = index
			}
		}
		if position < 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "settlement domain is absent from the handoff manifest"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"manifest": manifest, "domain": manifest.Domains[position], "leaf_index": position, "merkle_proof": handoffMerkleProof(leaves, position)})
	}
}

func (p *Plugin) domainMarkerHandler(key func([]byte) []byte) http.HandlerFunc {
	return p.domainRecordValueHandler(key, func() proto.Message { return new(ReplayMarker) })
}

func (p *Plugin) domainRecordValueHandler(key func([]byte) []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := decodePathHex(r.PathValue("domain"), 32)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "settlement domain must be 32-byte hexadecimal"})
			return
		}
		p.recordHandler(func(string) []byte { return key(domain) }, value)(w, r)
	}
}

func (p *Plugin) rotationQueuesReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		oldSetID, oldErr := strconv.ParseUint(r.PathValue("old"), 10, 64)
		newSetID, newErr := strconv.ParseUint(r.PathValue("new"), 10, 64)
		if oldErr != nil || newErr != nil || oldSetID == 0 || newSetID != oldSetID+1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid validator-set generation"})
			return
		}
		state, err := p.QueryState(height, &PluginStateReadRequest{Keys: []*PluginKeyRead{{QueryId: 1, Key: KeyForEpochClock()}}})
		if err != nil || len(state.Results) != 1 || len(state.Results[0].Entries) != 1 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "epoch handoff state is unavailable"})
			return
		}
		clock := new(EpochClock)
		if err = Unmarshal(state.Results[0].Entries[0].Value, clock); err != nil || clock.ValidatorSetId != oldSetID {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "validator generation is not current"})
			return
		}
		if !clock.ValidatorHandoffPrepared || len(clock.ValidatorHandoffDomains) == 0 || clock.ValidatorHandoffTimestamp == 0 {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "validator handoff attempt is not prepared"})
			return
		}
		if stateErr := validatePreparedValidatorHandoff(clock, p.config.ChainId); stateErr != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": stateErr.Msg})
			return
		}
		generation := validatorHandoffGeneration(clock)
		keys := make([]*PluginKeyRead, 0, len(clock.ValidatorHandoffDomains))
		for _, domainID := range clock.ValidatorHandoffDomains {
			keys = append(keys, &PluginKeyRead{QueryId: uint64(len(keys) + 1), Key: KeyForQueuedRotationIndex(domainID, oldSetID, newSetID)})
		}
		state, err = p.QueryState(height, &PluginStateReadRequest{Keys: keys})
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "validator handoff state is unavailable"})
			return
		}
		if len(state.Results) != len(keys) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "validator handoff state response is incomplete"})
			return
		}
		ready := true
		proofKeys := make([]*PluginKeyRead, 0, len(clock.ValidatorHandoffDomains))
		for index := range clock.ValidatorHandoffDomains {
			result := state.Results[index]
			if len(result.Entries) != 1 || len(result.Entries[0].Value) == 0 {
				ready = false
				continue
			}
			marker := new(ReplayMarker)
			if Unmarshal(result.Entries[0].Value, marker) != nil || len(marker.Id) == 0 {
				ready = false
				continue
			}
			proofKeys = append(proofKeys, &PluginKeyRead{QueryId: uint64(index + 1), Key: KeyForQuorumProof(marker.Id)})
		}
		if ready {
			proofState, proofErr := p.QueryState(height, &PluginStateReadRequest{Keys: proofKeys})
			if proofErr != nil || len(proofState.Results) != len(clock.ValidatorHandoffDomains) {
				ready = false
			} else {
				for index, result := range proofState.Results {
					proof := new(QuorumProof)
					if len(result.Entries) != 1 || Unmarshal(result.Entries[0].Value, proof) != nil ||
						proof.ProofKind != "validator-set-rotation-queued" ||
						!bytes.Equal(proof.SettlementDomainId, clock.ValidatorHandoffDomains[index]) ||
						!bytes.Equal(proof.HandoffGeneration, generation) || proof.HandoffTimestamp != clock.ValidatorHandoffTimestamp {
						ready = false
						break
					}
				}
			}
		}
		renewalPending := !ready && clock.ValidatorHandoffCancelling
		writeJSON(w, http.StatusOK, map[string]any{
			"ready": ready, "renewal_pending": renewalPending, "handoff_generation": generation,
			"handoff_timestamp": clock.ValidatorHandoffTimestamp, "handoff_attempt": clock.ValidatorHandoffAttempt,
			"epoch_end_height": clock.EndHeight, "native_chain_id": clock.ValidatorHandoffNativeChainId,
			"epoch": clock.CurrentEpoch, "old_validator_set_id": clock.ValidatorSetId,
			"new_validator_set_id":      clock.ValidatorSetId + 1,
			"frozen_roster_hash":        clock.ValidatorHandoffRosterHash,
			"frozen_domain_set_hash":    clock.ValidatorHandoffDomainSetHash,
			"outgoing_authority_cutoff": clock.ValidatorHandoffOutgoingAuthorityCutoff,
		})
	}
}

func loopbackListenAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type limitedListener struct {
	net.Listener
	semaphore chan struct{}
}

func newLimitedListener(listener net.Listener, maximum int) net.Listener {
	if maximum <= 0 {
		maximum = 1
	}
	return &limitedListener{Listener: listener, semaphore: make(chan struct{}, maximum)}
}

func (l *limitedListener) Accept() (net.Conn, error) {
	l.semaphore <- struct{}{}
	connection, err := l.Listener.Accept()
	if err != nil {
		<-l.semaphore
		return nil, err
	}
	return &limitedConnection{Conn: connection, release: func() { <-l.semaphore }}, nil
}

type limitedConnection struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

type fixedWindowLimiter struct {
	mu      sync.Mutex
	window  time.Time
	counts  map[string]int
	limit   int
	maximum int
}

func newFixedWindowLimiter(limit int) *fixedWindowLimiter {
	return &fixedWindowLimiter{window: time.Now(), counts: make(map[string]int), limit: limit, maximum: 4096}
}

func (l *fixedWindowLimiter) allow(identity string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.window) >= rpcRateWindow {
		l.window, l.counts = now, make(map[string]int)
	}
	if _, exists := l.counts[identity]; !exists && len(l.counts) >= l.maximum {
		return false
	}
	l.counts[identity]++
	return l.counts[identity] <= l.limit
}

func (p *Plugin) secureRPCHandler(next http.Handler) http.Handler {
	unauthenticated := newFixedWindowLimiter(rpcUnauthenticatedLimit)
	authenticated := newFixedWindowLimiter(rpcAuthenticatedLimit)
	concurrency := make(chan struct{}, max(1, p.config.RPCMaxConcurrent))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := r.RemoteAddr
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			identity = host
		}
		tokenValid := p.config.RPCAuthToken == "" || validBearerToken(r.Header.Get("Authorization"), p.config.RPCAuthToken)
		if !tokenValid {
			if !unauthenticated.allow(identity) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !authenticated.allow(identity) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		select {
		case concurrency <- struct{}{}:
			defer func() { <-concurrency }()
		default:
			http.Error(w, "server busy", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func validBearerToken(header, expected string) bool {
	if !strings.HasPrefix(header, "Bearer ") {
		return false
	}
	provided := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	providedHash, expectedHash := sha256.Sum256([]byte(provided)), sha256.Sum256([]byte(expected))
	return provided != "" && subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) == 1
}

func (p *Plugin) nextValidatorSetHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		state, err := p.QueryState(height, &PluginStateReadRequest{Keys: []*PluginKeyRead{{QueryId: 1, Key: KeyForEpochClock()}}})
		if err != nil || len(state.Results) != 1 || len(state.Results[0].Entries) != 1 || len(state.Results[0].Entries[0].Value) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "epoch clock is unavailable"})
			return
		}
		clock := new(EpochClock)
		if decodeErr := Unmarshal(state.Results[0].Entries[0].Value, clock); decodeErr != nil || clock.CurrentEpoch == ^uint64(0) {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "epoch clock is invalid"})
			return
		}
		state, err = p.QueryState(height, &PluginStateReadRequest{Ranges: []*PluginRangeRead{
			{QueryId: 2, Prefix: EpochValidatorPrefix(clock.CurrentEpoch + 1)},
			{QueryId: 3, Prefix: EpochValidatorPrefix(clock.CurrentEpoch)},
		}})
		if err != nil || len(state.Results) != 2 || len(state.Results[0].Entries) == 0 || len(state.Results[1].Entries) == 0 {
			writeJSON(w, http.StatusTooEarly, map[string]string{"error": "next validator set has not been frozen"})
			return
		}
		validators := make([]*Validator, 0, len(state.Results[0].Entries))
		for _, entry := range state.Results[0].Entries {
			validator := new(Validator)
			if decodeErr := Unmarshal(entry.Value, validator); decodeErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
				return
			}
			validators = append(validators, validator)
		}
		setID := clock.ValidatorSetId + 1
		if len(state.Results[0].Entries) == len(state.Results[1].Entries) {
			unchanged := true
			for index, entry := range state.Results[1].Entries {
				current := new(Validator)
				if decodeErr := Unmarshal(entry.Value, current); decodeErr != nil ||
					!bytes.Equal(current.PublicKey, validators[index].PublicKey) || current.StakedAmount != validators[index].StakedAmount {
					unchanged = false
					break
				}
			}
			if unchanged {
				setID = clock.ValidatorSetId
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"validator_set_id": setID, "validators": validators})
	}
}

// settlementBundleHandler returns a height-consistent settlement snapshot in
// one RPC call. The coordinator previously expanded the settlement index into
// three network reads per request, which made reconciliation latency grow
// linearly with both request count and validator RTT.
func (p *Plugin) settlementBundleHandler() http.HandlerFunc {
	const (
		// State is fetched in bounded chunks below, so the snapshot can cover a
		// complete high-throughput burst without forcing the coordinator through
		// repeated settle/finalize/index-removal waves.
		maxSettlementBundles = 4096
		stateReadChunkSize   = 256
	)
	type settlementBundle struct {
		Request     *RequestRecord     `json:"request"`
		Reservation *ReservationRecord `json:"reservation"`
		Executions  []*ExecutionRecord `json:"executions"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		requestIDs := make([]string, 0)
		if r.Method == http.MethodPost {
			var request struct {
				RequestIDs []string `json:"requestIds"`
			}
			decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
			if err := decoder.Decode(&request); err != nil || len(request.RequestIDs) == 0 || len(request.RequestIDs) > stateReadChunkSize {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requestIds must contain between 1 and 256 request IDs"})
				return
			}
			seen := make(map[string]struct{}, len(request.RequestIDs))
			for _, requestID := range request.RequestIDs {
				if requestID == "" {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requestIds contains an empty request ID"})
					return
				}
				if _, exists := seen[requestID]; exists {
					writeJSON(w, http.StatusBadRequest, map[string]string{"error": "requestIds contains a duplicate request ID"})
					return
				}
				seen[requestID] = struct{}{}
			}
			requestIDs = request.RequestIDs
		} else {
			entries, err := p.rpcRangePage(w, r, height, SettlementIndexPrefix())
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			for _, entry := range entries {
				pointer := new(RequestRecord)
				if decodeErr := Unmarshal(entry.Value, pointer); decodeErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
					return
				}
				if pointer.RequestId == "" {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settlement index contains an empty request ID"})
					return
				}
				requestIDs = append(requestIDs, pointer.RequestId)
				if len(requestIDs) == maxSettlementBundles {
					break
				}
			}
		}
		bundles := make([]settlementBundle, 0, len(requestIDs))
		requestKeys := make([]*PluginKeyRead, len(requestIDs))
		for index, requestID := range requestIDs {
			requestKeys[index] = &PluginKeyRead{QueryId: uint64(index + 1), Key: KeyForRequest(requestID)}
		}
		for start := 0; start < len(requestKeys); start += stateReadChunkSize {
			end := min(start+stateReadChunkSize, len(requestKeys))
			state, readErr := p.QueryState(height, &PluginStateReadRequest{Keys: requestKeys[start:end]})
			if readErr != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": readErr.Error()})
				return
			}
			for _, result := range state.Results {
				if len(result.Entries) != 1 || len(result.Entries[0].Value) == 0 {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settlement index references a missing request"})
					return
				}
				record := new(RequestRecord)
				if decodeErr := Unmarshal(result.Entries[0].Value, record); decodeErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
					return
				}
				if record.Status != "authorized" && record.Status != "ready" {
					continue
				}
				completed := false
				for _, assignment := range record.Assignments {
					completed = completed || assignment.Completed && assignment.ExecutionId != ""
				}
				if completed {
					bundles = append(bundles, settlementBundle{Request: record})
				}
			}
		}
		if len(bundles) == 0 {
			writeJSON(w, http.StatusOK, []settlementBundle{})
			return
		}
		keys := make([]*PluginKeyRead, 0, len(bundles)*2)
		type target struct {
			bundle    int
			execution bool
		}
		targets := make(map[uint64]target)
		var queryID uint64
		for bundleIndex := range bundles {
			queryID++
			keys = append(keys, &PluginKeyRead{QueryId: queryID, Key: KeyForReservation(bundles[bundleIndex].Request.SettlementDomainId, bundles[bundleIndex].Request.RequestId)})
			targets[queryID] = target{bundle: bundleIndex}
			for _, assignment := range bundles[bundleIndex].Request.Assignments {
				if !assignment.Completed || assignment.ExecutionId == "" {
					continue
				}
				queryID++
				keys = append(keys, &PluginKeyRead{QueryId: queryID, Key: KeyForExecution(assignment.ExecutionId)})
				targets[queryID] = target{bundle: bundleIndex, execution: true}
			}
		}
		for start := 0; start < len(keys); start += stateReadChunkSize {
			end := min(start+stateReadChunkSize, len(keys))
			state, err := p.QueryState(height, &PluginStateReadRequest{Keys: keys[start:end]})
			if err != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
				return
			}
			for _, result := range state.Results {
				target, exists := targets[result.QueryId]
				if !exists || len(result.Entries) != 1 || len(result.Entries[0].Value) == 0 {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settlement index references missing state"})
					return
				}
				if target.execution {
					execution := new(ExecutionRecord)
					if decodeErr := Unmarshal(result.Entries[0].Value, execution); decodeErr != nil {
						writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
						return
					}
					bundles[target.bundle].Executions = append(bundles[target.bundle].Executions, execution)
					continue
				}
				reservation := new(ReservationRecord)
				if decodeErr := Unmarshal(result.Entries[0].Value, reservation); decodeErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
					return
				}
				bundles[target.bundle].Reservation = reservation
			}
		}
		for _, bundle := range bundles {
			if bundle.Reservation == nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settlement reservation is missing"})
				return
			}
		}
		writeJSON(w, http.StatusOK, bundles)
	}
}

func (p *Plugin) settlementRequestListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		entries, err := p.rpcRangePage(w, r, height, SettlementIndexPrefix())
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		result := make([]string, 0)
		for _, entry := range entries {
			record := new(RequestRecord)
			if decodeErr := Unmarshal(entry.Value, record); decodeErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
				return
			}
			// Membership in this compact secondary index is the predicate. The
			// canonical request is loaded and status-checked by the consumer.
			result = append(result, record.RequestId)
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func (p *Plugin) assignmentListHandler() http.HandlerFunc {
	const assignmentReadChunkSize = 256
	return func(w http.ResponseWriter, r *http.Request) {
		owner, err := hex.DecodeString(strings.TrimPrefix(r.PathValue("id"), "0x"))
		if err != nil || len(owner) != 20 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "servicer address must be 20-byte hexadecimal"})
			return
		}
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		entries, queryErr := p.rpcRangePage(w, r, height, AssignmentIndexPrefix(owner))
		if queryErr != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": queryErr.Error()})
			return
		}
		type assignmentView struct {
			*RequestRecord
			ReservedBudget uint64 `json:"reserved_budget"`
		}
		requestIDs := make([]string, 0)
		for _, entry := range entries {
			pointer := new(RequestRecord)
			if decodeErr := Unmarshal(entry.Value, pointer); decodeErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
				return
			}
			if pointer.RequestId == "" {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "assignment index contains an empty request ID"})
				return
			}
			requestIDs = append(requestIDs, pointer.RequestId)
		}
		if len(requestIDs) == 0 {
			writeJSON(w, http.StatusOK, []assignmentView{})
			return
		}
		records := make([]*RequestRecord, 0, len(requestIDs))
		requestKeys := make([]*PluginKeyRead, len(requestIDs))
		for index, requestID := range requestIDs {
			requestKeys[index] = &PluginKeyRead{QueryId: uint64(index + 1), Key: KeyForRequest(requestID)}
		}
		for start := 0; start < len(requestKeys); start += assignmentReadChunkSize {
			end := min(start+assignmentReadChunkSize, len(requestKeys))
			canonical, readErr := p.QueryState(height, &PluginStateReadRequest{Keys: requestKeys[start:end]})
			if readErr != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": readErr.Error()})
				return
			}
			for _, item := range canonical.Results {
				if len(item.Entries) != 1 || len(item.Entries[0].Value) == 0 {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "assignment index references a missing request"})
					return
				}
				record := new(RequestRecord)
				if decodeErr := Unmarshal(item.Entries[0].Value, record); decodeErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
					return
				}
				if record.RequestId == "" {
					writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "assignment index references an invalid request"})
					return
				}
				records = append(records, record)
			}
		}
		keys := make([]*PluginKeyRead, len(records))
		for index, record := range records {
			keys[index] = &PluginKeyRead{QueryId: uint64(index + 1), Key: KeyForReservation(record.SettlementDomainId, record.RequestId)}
		}
		byQuery := make(map[uint64]*PluginReadResult, len(keys))
		for start := 0; start < len(keys); start += assignmentReadChunkSize {
			end := min(start+assignmentReadChunkSize, len(keys))
			reservations, readErr := p.QueryState(height, &PluginStateReadRequest{Keys: keys[start:end]})
			if readErr != nil {
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": readErr.Error()})
				return
			}
			for _, item := range reservations.Results {
				byQuery[item.QueryId] = item
			}
		}
		result := make([]assignmentView, 0, len(records))
		for index, record := range records {
			query := byQuery[uint64(index+1)]
			if query == nil || len(query.Entries) != 1 {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "active assignment reservation is missing"})
				return
			}
			reservation := new(ReservationRecord)
			if decodeErr := Unmarshal(query.Entries[0].Value, reservation); decodeErr != nil || reservation.RequestId != record.RequestId || reservation.Budget == 0 {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "active assignment reservation is invalid"})
				return
			}
			result = append(result, assignmentView{RequestRecord: record, ReservedBudget: reservation.Budget})
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func (p *Plugin) eventStreamHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		updates, unsubscribe, subscribed := p.subscribeBlocks()
		if !subscribed {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "stream subscriber limit reached"})
			return
		}
		defer unsubscribe()
		controller := http.NewResponseController(w)
		if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "streaming is unavailable"})
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		streamContext, cancel := context.WithTimeout(r.Context(), rpcStreamLifetime)
		defer cancel()
		heartbeat := time.NewTicker(10 * time.Second)
		defer heartbeat.Stop()
		write := func(payload string) bool {
			if err := controller.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return false
			}
			if _, err := io.WriteString(w, payload); err != nil {
				return false
			}
			return controller.Flush() == nil
		}
		for {
			select {
			case <-streamContext.Done():
				return
			case <-updates:
				if !write("event: block\ndata: committed\n\n") {
					return
				}
			case <-heartbeat.C:
				if !write(": keepalive\n\n") {
					return
				}
			}
		}
	}
}

func (p *Plugin) singletonHandler(key []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p.recordHandler(func(string) []byte { return key }, value)(w, r)
	}
}

func (p *Plugin) uintRecordHandler(key func(uint64) []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseUint(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "record identifier must be an unsigned integer"})
			return
		}
		p.recordHandler(func(string) []byte { return key(id) }, value)(w, r)
	}
}

func (p *Plugin) hexRecordHandler(size int, key func([]byte) []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		decoded, err := hex.DecodeString(strings.TrimPrefix(r.PathValue("id"), "0x"))
		if err != nil || len(decoded) != size {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "record identifier has invalid hexadecimal length"})
			return
		}
		p.recordHandler(func(string) []byte { return key(decoded) }, value)(w, r)
	}
}

func (p *Plugin) domainHexRecordHandler(size int, key func([]byte, []byte) []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := decodePathHex(r.PathValue("domain"), 32)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "settlement domain must be 32-byte hexadecimal"})
			return
		}
		id, err := decodePathHex(r.PathValue("id"), size)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "record identifier has invalid hexadecimal length"})
			return
		}
		p.recordHandler(func(string) []byte { return key(domain, id) }, value)(w, r)
	}
}

func (p *Plugin) domainRecordHandler(key func([]byte, string) []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := decodePathHex(r.PathValue("domain"), 32)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "settlement domain must be 32-byte hexadecimal"})
			return
		}
		p.recordHandler(func(id string) []byte { return key(domain, id) }, value)(w, r)
	}
}

func decodePathHex(value string, size int) ([]byte, error) {
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil || len(decoded) != size {
		return nil, fmt.Errorf("invalid hexadecimal value")
	}
	return decoded, nil
}

func (p *Plugin) quorumProofHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		proofID, err := hex.DecodeString(strings.TrimPrefix(r.PathValue("id"), "0x"))
		if err != nil || len(proofID) != 32 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "proof id must be 32-byte hexadecimal"})
			return
		}
		p.recordHandler(func(string) []byte { return KeyForQuorumProof(proofID) }, func() proto.Message { return new(QuorumProof) })(w, r)
	}
}

func (p *Plugin) rotationProofHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		oldSetID, oldErr := strconv.ParseUint(r.PathValue("old"), 10, 64)
		newSetID, newErr := strconv.ParseUint(r.PathValue("new"), 10, 64)
		domainID, domainErr := hex.DecodeString(strings.TrimPrefix(r.PathValue("domain"), "0x"))
		if oldErr != nil || newErr != nil || domainErr != nil || len(domainID) != 32 || oldSetID == 0 || newSetID != oldSetID+1 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "rotation set identifiers are invalid"})
			return
		}
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		index, err := p.QueryState(height, &PluginStateReadRequest{Keys: []*PluginKeyRead{{
			QueryId: 1, Key: KeyForRotationProofIndex(domainID, oldSetID, newSetID),
		}}})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		if len(index.Results) != 1 || len(index.Results[0].Entries) != 1 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "rotation proof not found"})
			return
		}
		marker := new(ReplayMarker)
		if decodeErr := Unmarshal(index.Results[0].Entries[0].Value, marker); decodeErr != nil || len(marker.Id) != 32 {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rotation proof index is invalid"})
			return
		}
		p.recordHandler(func(string) []byte { return KeyForQuorumProof(marker.Id) }, func() proto.Message { return new(QuorumProof) })(w, r)
	}
}

func (p *Plugin) settlementDomainAuthorityProofHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setID, setErr := strconv.ParseUint(r.PathValue("set"), 10, 64)
		domainID, domainErr := hex.DecodeString(strings.TrimPrefix(r.PathValue("domain"), "0x"))
		if setErr != nil || domainErr != nil || len(domainID) != 32 || setID == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authority set identifier is invalid"})
			return
		}
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		index, err := p.QueryState(height, &PluginStateReadRequest{Keys: []*PluginKeyRead{{
			QueryId: 1, Key: KeyForSettlementDomainAuthority(domainID, setID),
		}}})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		if len(index.Results) != 1 || len(index.Results[0].Entries) != 1 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "settlement-domain authority proof not found"})
			return
		}
		marker := new(ReplayMarker)
		if decodeErr := Unmarshal(index.Results[0].Entries[0].Value, marker); decodeErr != nil || len(marker.Id) != 32 {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "settlement-domain authority proof index is invalid"})
			return
		}
		p.recordHandler(func(string) []byte { return KeyForQuorumProof(marker.Id) }, func() proto.Message { return new(QuorumProof) })(w, r)
	}
}

func (p *Plugin) recordHandler(key func(string) []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		response, err := p.QueryState(height, &PluginStateReadRequest{Keys: []*PluginKeyRead{{QueryId: 1, Key: key(r.PathValue("id"))}}})
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		if len(response.Results) != 1 || len(response.Results[0].Entries) == 0 || len(response.Results[0].Entries[0].Value) == 0 {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "record not found"})
			return
		}
		record := value()
		if decodeErr := Unmarshal(response.Results[0].Entries[0].Value, record); decodeErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
			return
		}
		writeJSON(w, http.StatusOK, record)
	}
}

func (p *Plugin) listHandler(prefix []byte, value func() proto.Message) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		height, ok := queryHeight(w, r)
		if !ok {
			return
		}
		entries, err := p.rpcRangePage(w, r, height, prefix)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		result := make([]any, 0)
		for _, entry := range entries {
			record := value()
			if decodeErr := Unmarshal(entry.Value, record); decodeErr != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": decodeErr.Error()})
				return
			}
			if status := r.URL.Query().Get("status"); status != "" && !recordHasStatus(record, status) {
				continue
			}
			result = append(result, record)
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func (p *Plugin) rpcRangePage(w http.ResponseWriter, r *http.Request, height uint64, prefix []byte) ([]*PluginStateEntry, error) {
	limit := uint64(rpcPageSize)
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || parsed == 0 || parsed > rpcPageSize {
			return nil, ErrInvalidTransaction("pagination limit must be between one and 500")
		}
		limit = parsed
	}
	var startAfter []byte
	if cursor := r.URL.Query().Get("cursor"); cursor != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(cursor)
		if err != nil || !strings.HasPrefix(string(decoded), string(prefix)) {
			return nil, ErrInvalidTransaction("pagination cursor is invalid")
		}
		startAfter = decoded
	}
	response, err := p.QueryState(height, &PluginStateReadRequest{Ranges: []*PluginRangeRead{{
		QueryId: 1, Prefix: prefix, Limit: limit, StartAfter: startAfter,
	}}})
	if err != nil {
		return nil, err
	}
	if len(response.Results) != 1 {
		return nil, ErrState("unexpected paginated range response")
	}
	entries := response.Results[0].Entries
	if uint64(len(entries)) == limit {
		w.Header().Set("X-Takusen-Next-Cursor", base64.RawURLEncoding.EncodeToString(entries[len(entries)-1].Key))
	}
	return entries, nil
}

func recordHasStatus(record proto.Message, wanted string) bool {
	switch record := record.(type) {
	case *RequestRecord:
		return record.Status == wanted
	case *ReservationRecord:
		return record.Status == wanted
	case *SlashEvidence:
		return record.Status == wanted
	case *EpochAuthorization:
		return record.Status == wanted
	case *BridgeBurn:
		return record.Status == wanted
	default:
		return true
	}
}

func queryHeight(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	value := strings.TrimSpace(r.URL.Query().Get("height"))
	if value == "" {
		return 0, true
	}
	height, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "height must be an unsigned integer"})
		return 0, false
	}
	return height, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
