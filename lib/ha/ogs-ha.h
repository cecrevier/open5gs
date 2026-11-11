/* Copyright (C) 2026 Open5GS contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#ifndef OGS_HA_H
#define OGS_HA_H

#include <stddef.h>
#include <stdint.h>
#include <openssl/ssl.h>

/* An ordered durable replication stream, NOT a consensus or NF recovery
 * implementation. Callers must authorize the leader/epoch independently.
 * A durable ACK says nothing about NF hydration or permission to promote.
 * All APIs are single-threaded; one owner/event loop per journal/session. */
#define OGS_HA_HEADER_SIZE 64u
#define OGS_HA_MAX_PAYLOAD (1024u * 1024u)
#define OGS_HA_MAX_JOURNAL_SIZE (64u * 1024u * 1024u)
#define OGS_HA_ACK_SIZE 80u
#define OGS_HA_IO_TIMEOUT_MS 5000
#define OGS_HA_OK 0
#define OGS_HA_DUPLICATE 1
#define OGS_HA_ERROR (-1)

enum ogs_ha_component {
    OGS_HA_MME = 1, OGS_HA_AMF, OGS_HA_SGWC, OGS_HA_SGWU,
    OGS_HA_SMF, OGS_HA_UPF, OGS_HA_HSS, OGS_HA_PCRF,
    OGS_HA_PCSCF, OGS_HA_ICSCF, OGS_HA_SCSCF, OGS_HA_MEDIA,
    OGS_HA_UDM, OGS_HA_UDR, OGS_HA_AUSF, OGS_HA_PCF,
    OGS_HA_NRF, OGS_HA_NSSF, OGS_HA_BSF
};
enum ogs_ha_kind {
    OGS_HA_SNAPSHOT_BEGIN = 1, OGS_HA_UPSERT,
    OGS_HA_DELETE, OGS_HA_SNAPSHOT_END, OGS_HA_BARRIER
};

/* Canonical network-byte-order envelope; payloads require their own versioned
 * per-NF schema. Never send a raw C struct, pointer, key in a log, or FD. */
typedef struct {
    uint8_t cluster[16];
    uint64_t epoch;
    uint64_t sequence;
    uint16_t component;
    uint16_t kind;
    const uint8_t *payload;
    uint32_t payload_size;
} ogs_ha_record_t;

typedef struct ogs_ha_journal_s ogs_ha_journal_t;

/* Caller owns the encoded allocation; cleanse sensitive bytes before free(). */
int ogs_ha_encode(const ogs_ha_record_t *record, uint8_t **frame, size_t *size);
/* The returned payload borrows frame. CRC detects disk corruption, not forgery.
 * Authenticate every frame via the mTLS channel before accepting it. */
int ogs_ha_decode(const uint8_t *frame, size_t size, ogs_ha_record_t *record);

/* Private directory required. New files are 0600; symlinks, non-regular,
 * shared, wrong-owner and permissive files are rejected. Exclusive flock.
 * Strict recovery: an incomplete/corrupt journal fails without truncation. */
ogs_ha_journal_t *ogs_ha_journal_open(const char *path,
        const uint8_t cluster[16]);
void ogs_ha_journal_close(ogs_ha_journal_t *journal);
uint64_t ogs_ha_journal_sequence(const ogs_ha_journal_t *journal);
uint64_t ogs_ha_journal_epoch(const ogs_ha_journal_t *journal);
/* Append returns only after fdatasync. Only an identical last record can be
 * retried; conflicting duplicates, gaps, stale epochs and foreign clusters fail.
 * An IO failure permanently poisons this handle. Reopen/recover before retry.
 * The experimental journal is capped at 64 MiB; reaching it refuses new records.
 * Rotation/compaction is not implemented. Never delete a log to bypass the cap. */
int ogs_ha_journal_append(ogs_ha_journal_t *journal,
        const uint8_t *frame, size_t size);
/* Replay validates the entire stream before invoking callbacks. Callbacks
 * hydrate disposable shadow state; a callback failure must discard that state.
 * A snapshot is not complete until the adapter validates its END/barrier. */
typedef int (*ogs_ha_replay_fn)(const ogs_ha_record_t *record, void *data);
int ogs_ha_journal_replay(ogs_ha_journal_t *journal,
        ogs_ha_replay_fn callback, void *data);

/* TLS 1.3, mutual certificate verification, DNS SAN identity (no CN fallback).
 * Sets the connected socket nonblocking. Handshake and each send/receive have
 * an overall 5s network deadline, not a per-byte timeout. The caller owns the
 * socket, SSL and SSL_CTX lifetimes and must suppress SIGPIPE process-wide. */
SSL_CTX *ogs_ha_tls_context(const char *ca, const char *cert, const char *key);
SSL *ogs_ha_tls_session(SSL_CTX *ctx, int fd,
        const char *expected_peer_dns, int server);
/* Transport failure makes the session unusable: close, reconnect, retry the
 * same record. No resynchronization on a partially read/written TLS stream. */
int ogs_ha_send(SSL *session, const uint8_t *frame, size_t size);
int ogs_ha_receive(SSL *session, ogs_ha_journal_t *journal);

#endif
