# MME operator control

This adds a native, Linux-local O+M interface for requesting the MME load
rebalancing procedure in TS 23.401 §4.3.7.3. It is based on the S10 mobility
branch, not on state replication or an active/standby process takeover.

## Enable

Build the MME from this branch. Configure a private directory owned by the MME
service user (0700), then set `OPEN5GS_MME_OPERATOR_SOCKET` to a socket path in
that directory in the service environment. For systemd:

```ini
[Service]
RuntimeDirectory=open5gs-mme-operator
RuntimeDirectoryMode=0700
Environment=OPEN5GS_MME_OPERATOR_SOCKET=/run/open5gs-mme-operator/control.sock
```

The Unix datagram socket is 0600. Linux `SCM_CREDENTIALS` must identify root or
the MME's own effective UID. Existing socket paths are not silently replaced;
systemd should manage the runtime directory across restarts. Without the
environment setting the interface is disabled. No new TCP/HTTP listener or
mutating Prometheus endpoint is exposed.

## Protocol

Each datagram contains one JSON object, up to 2048 bytes. Bind the client to a
private local Unix socket and wait for one JSON reply. These operations exist:

```json
{"operation":"capabilities"}
```

```json
{"operation":"rebalance","request_id":"12345678-1234-1234-1234-123456789012","imsi":"001010000000101"}
```

The rebalance reply contains the same request ID. `status=requested` means the
MME started the procedure; it is not confirmation of arrival at another MME.
The last 64 request IDs and their UE/result bindings suppress duplicate
dispatch in this process lifetime. Reusing one ID for another UE is rejected.
A caller must not automatically retry an uncertain operation after an MME
restart. Native control does not maintain a persistent migration coordinator.

Kernel credentials are checked before a request is placed on the existing
MME event queue. Parsing and context actions then execute in the MME FSM's
serialized event handling. No HTTP worker manipulates UE contexts. Queue
insertion is nonblocking. A lost response is not evidence of non-execution.

## Procedure and eligibility

The UE must have a registered, connected, valid security context, an established
radio association, a serving gateway and PDN sessions. A configured S10 peer is
required. Concurrent gateway/mobility/release procedures are refused. Emergency
attachment, QCI 1/2 and high-priority ARP bearers are refused by this maintenance
operation; connected voice mobility needs radio-coordinated handover.

The MME sends Release Access Bearers using a distinct local transaction action.
Only an accepted response for the same UE proceeds to S1 release, with the
standard radio-network cause `load balancing TAU required`. The operation does
not delete the PDN or send a NAS Detach. A refused gateway response leaves the
radio path intact. S10 supplies context retrieval during subsequent inter-MME
TAU using the existing mobility implementation.

The eNodeB chooses the next MME using its pool/selection configuration. This
interface does not name or force an arbitrary destination, invent a radio
handover, move a PGW anchor or guarantee call/media continuity. An orchestrator
must verify target S1 connectivity, observe actual source/target UE state and
check retained PDN addressing before reporting completion.

## Validation

`unit mme-operator-test` runs production eligibility/parsing with context and
network dispatch fixtures; it checks the standard GTP release action, guards,
idempotent request IDs and Unix credential transport/file permissions. The
normal Open5GS unit suite also runs against this branch. These tests do not
qualify a particular eNodeB vendor's MME selection or a two-host deployment.
