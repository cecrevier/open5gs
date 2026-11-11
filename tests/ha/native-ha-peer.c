/* Test-only transport harness. Never installed or launched by an NF.
 * Copyright (C) 2026 Open5GS contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "ogs-ha.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

int __real_fdatasync(int fd);
int __wrap_fdatasync(int fd);
int __real_SSL_write_ex(SSL *ssl, const void *buf, size_t size, size_t *written);
int __wrap_SSL_write_ex(SSL *ssl, const void *buf, size_t size, size_t *written);
static int fail_sync, drop_ack, wrong_ack;
static uint8_t cluster[16] = {1, 2, 3};

int __wrap_fdatasync(int fd)
{
    if (fail_sync) { errno = EIO; return -1; }
    return __real_fdatasync(fd);
}

int __wrap_SSL_write_ex(SSL *ssl, const void *buf, size_t size, size_t *written)
{
    static uint8_t corrupt[OGS_HA_ACK_SIZE];
    if (size == OGS_HA_ACK_SIZE && !memcmp(buf, "OGHAACK1", 8)) {
        if (drop_ack) { *written = 0; return 0; }
        if (wrong_ack) {
            memcpy(corrupt, buf, size);
            corrupt[size - 1] ^= 1;
            return __real_SSL_write_ex(ssl, corrupt, size, written);
        }
    }
    return __real_SSL_write_ex(ssl, buf, size, written);
}

static int send_record(SSL *ssl, uint64_t sequence, uint16_t kind,
        const uint8_t *payload, uint32_t size)
{
    uint8_t *frame;
    size_t length;
    int rv;
    ogs_ha_record_t r = {0};
    memcpy(r.cluster, cluster, 16);
    r.epoch = 7; r.sequence = sequence; r.component = OGS_HA_MME;
    r.kind = kind; r.payload = payload; r.payload_size = size;
    if (ogs_ha_encode(&r, &frame, &length) != OGS_HA_OK) return OGS_HA_ERROR;
    rv = ogs_ha_send(ssl, frame, length);
    OPENSSL_cleanse(frame, length);
    free(frame);
    return rv;
}

static int client(SSL *ssl, const char *mode)
{
    uint8_t *payload;
    size_t i;
    int rv;
    if (!strcmp(mode, "stall")) {
        struct timespec interval = {0, 800000000};
        for (i = 0; i < 20; i++) {
            size_t sent = 0;
            if (SSL_write_ex(ssl, "O", 1, &sent) != 1 || sent != 1)
                return OGS_HA_ERROR;
            nanosleep(&interval, NULL);
        }
        return OGS_HA_ERROR;
    }
    if (!strcmp(mode, "foreign")) cluster[15] = 1;
    if (strcmp(mode, "good"))
        return send_record(ssl, !strcmp(mode, "gap") ? 2 : 1,
                OGS_HA_UPSERT, (const uint8_t *)"synthetic-only", 14);
    if (send_record(ssl, 1, OGS_HA_SNAPSHOT_BEGIN,
                (const uint8_t *)"synthetic-v1", 12)) return OGS_HA_ERROR;
    payload = malloc(OGS_HA_MAX_PAYLOAD);
    if (!payload) return OGS_HA_ERROR;
    for (i = 0; i < OGS_HA_MAX_PAYLOAD; i++) payload[i] = (uint8_t)(i % 251);
    rv = send_record(ssl, 2, OGS_HA_UPSERT, payload, OGS_HA_MAX_PAYLOAD);
    if (rv == OGS_HA_OK)
        rv = send_record(ssl, 2, OGS_HA_UPSERT, payload, OGS_HA_MAX_PAYLOAD);
    free(payload);
    if (rv != OGS_HA_OK || send_record(ssl, 3, OGS_HA_DELETE,
                (const uint8_t *)"ue-test", 7) ||
            send_record(ssl, 4, OGS_HA_SNAPSHOT_END, NULL, 0) ||
            send_record(ssl, 5, OGS_HA_BARRIER, NULL, 0)) return OGS_HA_ERROR;
    return OGS_HA_OK;
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    SSL *ssl;
    ogs_ha_journal_t *journal = NULL;
    int fd, server, rv = OGS_HA_ERROR, i, count;
    signal(SIGPIPE, SIG_IGN);
    if (argc == 3 && !strcmp(argv[1], "inspect")) {
        journal = ogs_ha_journal_open(argv[2], cluster);
        if (!journal) return 2;
        printf("sequence=%llu epoch=%llu\n",
                (unsigned long long)ogs_ha_journal_sequence(journal),
                (unsigned long long)ogs_ha_journal_epoch(journal));
        ogs_ha_journal_close(journal);
        return 0;
    }
    /* role fd ca cert key expected-peer mode [journal count] */
    if (argc < 9) return 2;
    server = !strcmp(argv[1], "server");
    if (server && argc != 11) return 2;
    fd = atoi(argv[2]);
    ctx = ogs_ha_tls_context(argv[3], argv[4], argv[5]);
    if (!ctx) return 3;
    ssl = ogs_ha_tls_session(ctx, fd, argv[6], server);
    if (!ssl) { SSL_CTX_free(ctx); close(fd); return 4; }
    if (!server) rv = client(ssl, argv[7]);
    else {
        journal = ogs_ha_journal_open(argv[8], cluster);
        count = atoi(argv[9]);
        fail_sync = !strcmp(argv[7], "sync-fail");
        drop_ack = !strcmp(argv[7], "drop-ack");
        wrong_ack = !strcmp(argv[7], "wrong-ack");
        if (journal) {
            rv = OGS_HA_OK;
            for (i = 0; i < count; i++) {
                rv = ogs_ha_receive(ssl, journal);
                if (rv != OGS_HA_OK) break;
            }
            printf("sequence=%llu epoch=%llu\n",
                    (unsigned long long)ogs_ha_journal_sequence(journal),
                    (unsigned long long)ogs_ha_journal_epoch(journal));
        }
    }
    ogs_ha_journal_close(journal);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(fd);
    return rv == OGS_HA_OK ? 0 : 1;
}
