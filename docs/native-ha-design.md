# Native full-core HA: replication foundation

## Status

This branch starts native Open5GS/IMS HA development. **It does not provide
operational HA, seamless failover, or an NMS HA module yet.** No existing NF
calls the new library, and no process is allowed to promote a standby through
it. The implementation is opt-in with `-Dnative_ha=true`, off by default.

The requested deployment has primary management address `172.20.8.62` and
planned secondary `172.20.8.63`. The secondary is not installed. The requirement
is survival of existing calls and UE sessions, without an imposed reattach,
address change or call reestablishment. No hypervisor dependency is permitted.
These addresses are deployment context, not compiled defaults or floating
service addresses. No production service or network setting is changed here.

### Implemented and exercised

* A canonical, versioned, bounded binary replication envelope, independent of
  pointer size, padding, host endianness and in-memory Open5GS structures.
* TLS 1.3 with mutual certificate validation and explicit DNS SAN identity for
  both peers. Common-name fallback and wildcard identities are rejected.
* An ordered private journal with a cluster UUID, monotonic epoch and contiguous
  sequence. A CRC covers each complete envelope/payload; it is not authentication.
* ACK only after `fdatasync`, bound to the cluster, epoch, sequence and SHA-256
  of the exact request. Conflicting duplicates and wrong ACK hashes fail.
* Exact retry of the last record, including after a receiver restart when an
  ACK was lost. Recovery syncs surviving bytes before an ACK can be returned.
* Exclusive file ownership, 0600 regular files in a private directory, refusal
  of symlink/hardlink journals, and a 64 MiB experimental journal cap.
* Strict recovery: truncated/corrupt records are refused without changing the
  file. Full validation precedes replay into disposable shadow state.
* A five-second overall network deadline per handshake/send/receive, including
  slowly fragmented frames. Network failures require a fresh TLS connection.

Tests use two independent C processes over loopback TCP, ephemeral certificates
and synthetic state. The harness injects lost ACKs, wrong ACK hashes and disk
sync errors. Unit tests also inject partial writes/ENOSPC, corrupt every byte
of a frame, and try every incomplete-record boundary. They do not simulate an
eNB, an established IMS call, or an Open5GS NF failure.

## Build and test

On Linux, with the normal Open5GS development dependencies plus OpenSSL 3
development headers, the `openssl` command and Python 3:

```sh
meson setup build-ha -Dnative_ha=true
meson compile -C build-ha native-ha-test native-ha-peer
meson test -C build-ha --suite native-ha --print-errorlogs
```

The test executables are not installed. GNU linker wrappers inject faults only
into tests; production library code does not contain test fault switches.

## What the foundation deliberately cannot certify

`durable sequence` means a replication record reached disk. It does **not**
mean a session has been reconstructed, a snapshot is complete, a writer owns
a valid quorum lease, the previous writer is fenced, or traffic can move.
An epoch inside a TLS record is not proof of leadership. The library checks
ordering, not the authority that allocated an epoch. The authenticated caller
must eventually supply that authority through a separate checked interface.

Snapshot BEGIN/END/barrier records are envelope types, not implemented snapshot
transactions. Until NF adapters validate a complete snapshot and its subsequent
committed changes, the receiver is not ready. DELETE payloads need explicit
stable object identity and generation before they can delete an NF object.

There is no log compaction, snapshot checkpoint rotation, encrypted storage,
automatic resynchronization or long-term key management yet. The capped journal
refuses new writes when full; deleting a log is not a recovery procedure.
Payloads may eventually include NAS/IMS secrets, so no real UE state should
be sent through this experimental implementation. File permissions do not
replace an agreed policy for encryption and access to storage.

## Native architecture to implement

### Ownership, replication and fencing

Use one ordered cluster stream, owned by a native HA coordinator on each node.
NF adapters submit versioned records over an authenticated local interface;
they must not each start a competing sequence at one in the same journal.
The coordinator durably replicates state and returns a commit result. A
standby builds shadow state before being considered eligible.

The coordinator still needs a proven quorum/fencing mechanism. Two nodes alone
cannot safely distinguish a dead primary from a partitioned primary. Provision
an independent witness/quorum service or a verifiable fencing mechanism before
automatic takeover. A witness must survive the failure of either core host.
It is a software role; it does not require a hypervisor. A heartbeat, a failed
ping, a service PID, or a movable IP is not a fencing proof.

Gate externally visible signaling and resource allocation on a current
authority epoch. Replicate NAS counter/security transitions before exposing
their corresponding messages. Async NF hooks must defer their outbound work
until commit; do not block the existing NF event loop on a TLS round trip.
Bound pending work and define behavior when the replica is unavailable.

A promotion must verify, at minimum:

1. Current quorum authorization and exclusion of the former writer.
2. Compatible binaries, configuration and payload schema versions.
3. A fully hydrated consistent snapshot and all required committed mutations.
4. Supported takeover for every protected transport and dataplane endpoint.
5. Database availability and authoritative security/allocation state.

No provider, stale replica, unknown status, or failed check means no automatic
promotion. A successful MongoDB election cannot satisfy the other checks.

### State providers and source boundaries

| Area | Required state and invariants | Starting source boundary / integration |
| --- | --- | --- |
| MME | IMSI/GUTI identities, S1AP mapping, security keys and NAS counters, EMM/ESM procedure state, timers, PDN/bearer objects, S11 transactions | `src/mme/mme-context.*`, `emm-sm.c`, `esm-sm.c`, `nas-path.c`, `mme-s10*` |
| AMF | UE identity/security, NGAP mapping, registration/procedure state, timers, SMF bindings and SBI operations | `src/amf/context.*`, GMM/NGAP/NAS/SBI paths |
| SGW-C / SMF | Stable session/TEID/SEID identities, bearer/PDU state, IP allocation, GTP/PFCP transactions and recovery state, charging/policy bindings | `src/sgwc/context.*`, `src/smf/context.*`, GTP/PFCP/SBI handlers |
| SGW-U / UPF | PDR/FAR/QER/URR/BAR objects, tunnel endpoints, UE addressing/routes, usage counters and dataplane resources | `src/sgwu/context.*`, `src/upf/context.*`, `lib/pfcp`, tunnel/network setup |
| HSS / UDM / UDR / AUSF | Authoritative subscriber data, serving-node bindings, authentication vectors/SQN and related state; atomic updates | `lib/dbi`, NF handlers and MongoDB replica-set deployment |
| PCRF / PCF / discovery | Policy sessions, bindings, NF registrations/subscriptions and timers, in-flight Diameter/SBI operations | `src/pcrf`, `src/pcf`, `src/nrf`, `src/nssf`, `src/bsf`, Diameter/SBI libraries |
| IMS registration and SIP | P-/I-/S-CSCF registrations, routes, dialog and transaction state, charging and any IMS HSS/SQL dependency | Deployed Kamailio configuration/modules, IMS database schema and dependencies must be inventoried |
| IMS security/media | IPsec SAs, SPI allocation, sequence and anti-replay state; RTP/SRTP ports, keys, rollover/sequence state and media forwarding | Kamailio IMS IPsec module, kernel XFRM, deployed RTPengine/version/configuration |
| Transport and endpoints | SCTP association state and peer bindings; stable GTP/PFCP/SIP/media endpoints; required TCP/TLS session behavior and routing/NAT/conntrack | `lib/sctp`, kernel transport and network state; RAN/IMS interoperability tests |

The S10 branch already exports EPS MM context, PDN/bearer information and
mobility procedures. Reuse its schema/validation where appropriate, but do not
call an inter-MME relocation a standby restore. Its target identity, protocol
actions, security ownership and deletion rules differ from recovery of the
same logical failed node. The original MME's SCTP socket is not transferred
by copying an S10 payload.

Existing PFCP restoration paths in `src/smf/pfcp-sm.c` and
`src/sgwc/pfcp-sm.c` are useful starting points. Their availability does not
prove recovery of a failed SMF/SGW-C process or all EPS/5GS sessions. Evaluate
their actual supported branches and failure behavior before advertising them.

### Databases and installation

The inspected MongoDB instance was standalone (`hello` returned no replica-set
name). Plan and test its conversion separately, including backups, version
compatibility, majority behavior and authentication. Determine all IMS SQL/HSS
and NMS persistence dependencies before declaring the whole core protected.
An independent third data-bearing voter is preferable to treating a witness
as another copy of the data. Do not automatically rewrite live databases.

The eventual installer should inventory supported host/package versions,
permissions, time synchronization, key provisioning, service artifacts and
network prerequisites. Install software separately from activating ownership
or modifying live core endpoints. It must report unsupported components and
failed prerequisites, and preserve the existing deployment on failure.

### NMS module

Add the HA management module after a versioned native status/control API can
report actual provider state. Display each node, authority epoch, lease and
fencing state, durable/applied sequence, lag, snapshot generation, provider
coverage and database status. An active systemd unit is service health only.
Do not display "sessions protected" based on a PID or S10 configuration.

Control actions require admin authorization and an audit entry. A planned
switchover must return concrete refusal reasons if any provider is unready.
An unplanned takeover must use the same native authority and fencing checks;
the browser must not be responsible for detecting failures or making quorum.

## Acceptance before claiming call/session continuity

Build an isolated two-core/RAN/IMS environment first. Preserve a continuous
bidirectional traffic flow and a real IMS call during every test, and capture
both signaling and media. Check allocated UE IPs, bearer/PDU identities,
security counters, packet loss/reordering and the ability to continue SIP
operations on the same call after takeover. Measure interruption rather than
inferring continuity from a newly registered subscriber or a successful ping.

Inject abrupt process/host failure, primary/secondary network partitions,
lost replication ACKs, disk failure/full disk, witness loss, stale replicas,
reboot of the former primary, incompatible payload versions and failure during
snapshot transfer. Exercise two APNs, dedicated voice bearers, idle and active
UEs, multiple calls and sustained traffic. Verify no dual active writer, no
NAS/security counter rollback or reuse, no IP/TEID/SPI collision, no forced UE
reattach, no call reestablishment and no accidental deletion of newer state.

Transport takeover is an explicit qualification gate. Either preserve the
association through a supported native mechanism, or demonstrate with the
actual RAN that recovery preserves its existing radio bearers and calls. Do
not assume SCTP multihoming alone supplies application/process redundancy.

Physical validation on `.62`/`.63` remains pending secondary installation,
an agreed authority/fencing topology and completion of the state providers.

## References

* [S10 mobility with SGW relocation](https://github.com/open5gs/open5gs/pull/5019)
  and the branch's `docs/s10-design.md`.
* [Kamailio IMS IPsec registrar](https://www.kamailio.org/docs/modules/stable/modules/ims_ipsec_pcscf.html)
  for its IMS registration and kernel IPsec integration.
* [MongoDB replica-set architectures](https://www.mongodb.com/docs/manual/core/replica-set-architectures/)
  for voting and majority requirements. Database redundancy is one part of
  the architecture, not a substitute for NF runtime replication.
