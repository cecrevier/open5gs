# LTE Cell Broadcast integration

This branch integrates the SBc-AP contributions from Open5GS #4822 and #4864
with the existing S10/operator branch and adds explicit TAI routing to the RAN.
Original ASN.1 files and author notices are retained. Credit: Mirko Kovačević
and Arnaud DJOUM (arnaudsoutenance-netizen).

## Enablement

Build/install this MME and its matching shared libraries in a separate prefix.
An unmodified MME binary cannot gain SBc-AP by adding YAML alone. The SBc-AP
listener is disabled when no server is configured:

```yaml
mme:
  sbcap:
    server:
      - address: 127.0.0.2
        port: 29168
```

The companion NMS installs a private OsmoCBC service whose SBc-AP client uses
this loopback endpoint. Configure transport reachability and trusted CBC peers
for a distributed deployment. The native contribution's listener is IPv4.

## Targeting and bounded parsing

The CBC can send a List-of-TAIs containing 1–16 PLMN/TAC pairs. An empty,
malformed or oversized explicit list is refused without global fallback.
PLMN identities preserve two- versus three-digit MNCs. Unknown warning-area
forms are refused rather than silently widening the target area.

Only eNodeBs with completed S1 setup and a matching supported TAI receive the
request. A multi-TAI eNodeB also receives the complete TAI Warning Area List in
the S1AP PDU, so its other tracking areas are not implicitly selected. The
same scope is preserved on S1AP Kill requests.

Message/serial identifiers and warning content lengths are validated before
reading/copying their buffers. Text content can use the standard maximum of
9600 octets at this interface. Binary payloads are not logged as C strings.
An MME response reports acceptance only after at least one matching eNodeB
send path succeeds; this is not proof of display on a handset.

The NMS workflow exposes text-based LTE CBS/CMAS messages. ETWS primary-warning
handling and 5G AMF/N50 are outside this integration's exposed functionality.

## Validation

- MME and unit targets compile alongside S10/operator code.
- `sbcap-message-test` encodes/decodes real S1AP write and kill requests and
  checks every target PLMN/TAC, including distinct MNC lengths.
- `sbc-routing-test` runs production routing against eNodeB/send fixtures:
  same TAC with another PLMN is excluded, another TAC is excluded, multiple
  matching TAIs work, disconnected radios and empty explicit scope are excluded.
- The complete Open5GS unit suite is run for the integration.
- The companion CBC's real REST → event loop → SCTP write/stop exchange is
  tested in a loopback-only network namespace, with no path to a real RAN.

No actual broadcast or handset reception is asserted by these tests. Real RAN
qualification must cover supported alert categories, encoding and cancellation.

References: 3GPP TS 23.041, TS 29.168 and TS 36.413 §9.2.1.46.
