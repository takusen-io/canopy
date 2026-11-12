# Takusen native module

This branch customizes the Go plugin as Takusen's Canopy-native state machine. It adds validator-quorum enclave registration, governed protocol parameters and settlement domains, epoch-queued bonded-servicer economics, producer rewards, EVM deposit observations, domain-scoped credit reservations, deterministic model assignments, signed execution receipts, and atomic settlement observations.

Finalized deposits create replay-protected, settlement-domain-scoped records and increment the requester's credit account for that domain only after strict stake-weighted validator quorum. Off-chain EIP-712 authorization atomically reserves witnessed credit. Execution records reservation spend, and one exact `settleBatch` transaction moves spend to settled credit and releases the unused budget. These records are queryable under `/v1/takusen/deposits`, `/credits`, and `/reservations`.

Protocol parameters use Canopy's native `changeParameter` proposal lifecycle and require a complete canonical document with a monotonic revision. Parameters cover model/provider allowlisting, PCR policies, fees/margins, validator quorum, deadlines/retries, minimum bonds, slash rates, epoch emissions, treasury allocation, governed settlement domains, and bridge limits. Provider prices and per-model budget schedules are not governed: the provider-reported cost authenticated and signed by the TEE is authoritative, and each assignment's all-in cap is its deterministic equal share of the request budget. A request-specific authorization expires at a governed Canopy height; its unique request ID and one-shot state transition provide replay protection. EOA authorizations use the state-independent direct path, while ERC-1271 observations bind one safe settlement-chain block number/hash into the quorum subject. Request admission spends only finalized credit, never a provisional low-finality deposit. Requester-selected agreement thresholds are display metadata only: every assignment runs or exhausts retries before request-level settlement. Every observation and conflict claim is keyed by an immutable validator-set ID and epoch and stores the observer's snapshot weight plus the snapshot total, so votes cannot cross snapshots or gain weight retroactively. A minority finalization vote leaves the request in settlement discovery until quorum or a valid certificate completes the terminal transition.

The canonical TAKU reward-chain domain's `LockedForCanopy` calls mint native balances only after safe-finality exact independent call/event verification and quorum, with transaction-hash, nonce, per-transfer, and per-epoch replay/risk limits. Native burns create immutable release records and remain pending until validators observe their safe canonical call/event. If reward or burn relay spans a validator rotation, the current committee may re-certify the same immutable allocation or burn fields; the epoch number and burn ID remain the replay nullifiers. Servicer stake edits apply at epoch boundaries; decreases enter governed unbonding, withdrawals require maturity, slash evidence requires quorum, and rewards support producer payout mappings and auto-compounding. Every plugin transaction pays the governed native send fee inside the same atomic state transaction as plugin delivery. Producer payout mappings are restricted to current/prepared validators or identities recorded by consensus after actual block production.

At every governed epoch boundary (3600 blocks by default), end-block processing records producer participation and writes a deterministic `EpochAuthorization`. Each epoch snapshots its duration and validator-handoff lead at entry, so governance changes schedule only the following epoch. If the preparation cutoff was missed, end block prepares immediately and extends the current boundary rather than deadlocking. Its reward digest exactly matches `TakusenToken.mintEpoch`; allocations are proportional to eligible blocks and include the governed treasury share. Buyback automation is not part of this module.

## EVM BDN proof export

`takusenSubmitQuorumSignature` carries an active validator's second BDN signature over the exact 32-byte, domain-separated EVM contract digest. The transaction itself is independently authenticated by Canopy. Once active signer stake is strictly greater than two thirds, the plugin stores a `QuorumProof` under `/v1/takusen/quorum-proofs/{proof-id}`.

The roster is sorted by compressed G1 public key. Bitmap bit `i` (least-significant bit first) selects roster member `i`. A persisted proof contains only its identity and digest, validator-set ID, signer bitmap, EIP-2537 aggregate signature, signed/total weights, and creation height. The active validator set supplies the roster and weighted EIP-2537 public keys needed by each domain verifier.

Prepared validator rotations preserve each exact raw uint64 Canopy voting power in the verifier's uint96 field. Normalized or approximate rosters are rejected, including any encoding that would turn an exact-two-thirds coalition into strict quorum. Rotation claims and direct proof indexes include the settlement domain. The outgoing committee queues the prepared roster independently on every active verifier; queueing freezes ordinary quorum effects while retaining old-quorum cancellation. Validators attest only after the pending state is finalized on that EVM chain. End-block refuses to cross the epoch boundary until every governed active domain has this queue record. Once Canopy activates the new roster, that incoming committee signs each verifier's activation digest. EVM-local block height cannot activate a committee.

Consensus range pages use a prefix-bound full-key continuation cursor backed by native Pebble and transaction-index seeks. Core excludes the cursor in the requested direction, and the plugin rejects duplicate, reordered, or out-of-prefix pages. Direct rotation-proof, pending-slash, latest-epoch, requester-scoped provisional-reservation, and active-servicer indexes avoid permanent-history scans in handoff, slashing, deposit resolution, enclave revocation, and assignment. Slash application is limited to 256 records per boundary block and resumes from persisted pending state.

The EVM proof argument is `abi.encode(bytes aggregateSignatureEIP2537, bytes signerBitmap)`. `plugin/go/contract/quorum_vector_test.go` and Takusen's `contracts/test/BDNQuorumVerifier.t.sol` share a fixed cross-language vector.

The core/plugin begin-block request includes the previous finalized block hash. Takusen uses that trusted value with the request input hash and model identifier to derive assignments.

Run the two-validator development network from the Canopy repository root:

```sh
docker compose -f plugin/go/compose.yaml up -d --build
```

The query RPC is at `http://localhost:50002`; the Takusen plugin RPC is at `http://localhost:50010`. The second node exposes query RPC `40002` and plugin RPC `50011`. Host publication is loopback-only. Inside each container the plugin uses `TAKUSEN_PLUGIN_RPC_TOKEN`; authorized clients send the same value as `CANOPY_PLUGIN_TOKEN`. Non-loopback listeners without a token are refused. The HTTP server bounds accepted connections, concurrent handlers, request identities, and subscribers; SSE writes have deadlines and streams expire after 30 seconds.

Run the native consensus integration test after both nodes are healthy:

```sh
cd plugin/go
TAKUSEN_E2E=1 go test -run TestTakusenConsensusE2E -v -count=1 -timeout=5m
```

The test commits the complete registration → bonding → deposit → reservation → authorization → assignment → execution → settlement → release lifecycle through both validators. The local validator keys are fixture keys from `.docker/volumes`; production validator observers must run independently and must not expose their keys to an application process.
