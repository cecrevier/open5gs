/* Copyright (C) 2026 Open5GS contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "ogs-ha.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define FILE_HEADER 32u

struct ogs_ha_journal_s {
    int fd;
    int poisoned;
    uint8_t cluster[16];
    uint64_t epoch;
    uint64_t sequence;
    off_t end;
    uint8_t digest[32];
};

static void clear_free(void *data, size_t size)
{
    OPENSSL_cleanse(data, size);
    free(data);
}

static uint64_t get_be(const uint8_t *p, size_t n)
{
    uint64_t v = 0;
    while (n--) v = (v << 8) | *p++;
    return v;
}

static void put_be(uint8_t *p, uint64_t v, size_t n)
{
    while (n) { p[--n] = (uint8_t)v; v >>= 8; }
}

static int nonzero(const uint8_t *p, size_t n)
{
    uint8_t v = 0;
    while (n--) v |= *p++;
    return v != 0;
}

/* Covers the envelope and payload, with the checksum field treated as zero. */
static uint32_t crc32(const uint8_t *p, size_t n)
{
    uint32_t crc = UINT32_MAX;
    size_t i;
    unsigned bit;
    for (i = 0; i < n; i++) {
        crc ^= (i >= 56 && i < 60) ? 0 : p[i];
        for (bit = 0; bit < 8; bit++)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

static int sha256(const uint8_t *p, size_t n, uint8_t digest[32])
{
    unsigned length = 0;
    return EVP_Digest(p, n, digest, &length, EVP_sha256(), NULL) == 1 &&
        length == 32 ? OGS_HA_OK : OGS_HA_ERROR;
}

int ogs_ha_encode(const ogs_ha_record_t *r, uint8_t **frame, size_t *size)
{
    uint8_t *p;
    if (!r || !frame || !size || !nonzero(r->cluster, 16) ||
            !r->epoch || !r->sequence || r->component < OGS_HA_MME ||
            r->component > OGS_HA_BSF || r->kind < OGS_HA_SNAPSHOT_BEGIN ||
            r->kind > OGS_HA_BARRIER || r->payload_size > OGS_HA_MAX_PAYLOAD ||
            (r->payload_size && !r->payload)) return OGS_HA_ERROR;
    p = calloc(1, OGS_HA_HEADER_SIZE + r->payload_size);
    if (!p) return OGS_HA_ERROR;
    memcpy(p, "OGHA", 4);
    put_be(p + 4, 1, 2);
    put_be(p + 6, OGS_HA_HEADER_SIZE, 2);
    memcpy(p + 8, r->cluster, 16);
    put_be(p + 24, r->epoch, 8);
    put_be(p + 32, r->sequence, 8);
    put_be(p + 40, r->component, 2);
    put_be(p + 42, r->kind, 2);
    put_be(p + 44, r->payload_size, 4);
    if (r->payload_size)
        memcpy(p + OGS_HA_HEADER_SIZE, r->payload, r->payload_size);
    *size = OGS_HA_HEADER_SIZE + r->payload_size;
    put_be(p + 56, crc32(p, *size), 4);
    *frame = p;
    return OGS_HA_OK;
}

static int header_size(const uint8_t *p, size_t *size)
{
    uint64_t n;
    if (memcmp(p, "OGHA", 4) || get_be(p + 4, 2) != 1 ||
            get_be(p + 6, 2) != OGS_HA_HEADER_SIZE ||
            nonzero(p + 48, 8) || nonzero(p + 60, 4)) return OGS_HA_ERROR;
    n = get_be(p + 44, 4);
    if (n > OGS_HA_MAX_PAYLOAD) return OGS_HA_ERROR;
    *size = OGS_HA_HEADER_SIZE + (size_t)n;
    return OGS_HA_OK;
}

int ogs_ha_decode(const uint8_t *p, size_t size, ogs_ha_record_t *r)
{
    ogs_ha_record_t out;
    size_t expected;
    if (!p || !r || size < OGS_HA_HEADER_SIZE ||
            header_size(p, &expected) != OGS_HA_OK || size != expected ||
            get_be(p + 56, 4) != crc32(p, size)) return OGS_HA_ERROR;
    memset(&out, 0, sizeof(out));
    memcpy(out.cluster, p + 8, 16);
    out.epoch = get_be(p + 24, 8);
    out.sequence = get_be(p + 32, 8);
    out.component = (uint16_t)get_be(p + 40, 2);
    out.kind = (uint16_t)get_be(p + 42, 2);
    out.payload_size = (uint32_t)get_be(p + 44, 4);
    out.payload = p + OGS_HA_HEADER_SIZE;
    if (!nonzero(out.cluster, 16) || !out.epoch || !out.sequence ||
            out.component < OGS_HA_MME || out.component > OGS_HA_BSF ||
            out.kind < OGS_HA_SNAPSHOT_BEGIN || out.kind > OGS_HA_BARRIER)
        return OGS_HA_ERROR;
    *r = out;
    return OGS_HA_OK;
}

static int read_at(int fd, uint8_t *p, size_t size, off_t offset)
{
    while (size) {
        ssize_t n = pread(fd, p, size, offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return OGS_HA_ERROR;
        p += n; size -= (size_t)n; offset += n;
    }
    return OGS_HA_OK;
}

static int write_all(int fd, const uint8_t *p, size_t size)
{
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return OGS_HA_ERROR;
        p += n; size -= (size_t)n;
    }
    return OGS_HA_OK;
}

/* Validate/replay using pread: callers never depend on a shared file offset.
 * The private directory and exclusive lock are part of the trust boundary. */
static int scan(ogs_ha_journal_t *j, ogs_ha_replay_fn callback, void *data)
{
    struct stat st;
    off_t offset = FILE_HEADER;
    uint64_t epoch = 0, sequence = 0;
    uint8_t header[OGS_HA_HEADER_SIZE], file_header[FILE_HEADER];
    uint8_t digest[32] = {0};
    if (fstat(j->fd, &st) || st.st_size < FILE_HEADER ||
            st.st_size > OGS_HA_MAX_JOURNAL_SIZE ||
            read_at(j->fd, file_header, FILE_HEADER, 0) != OGS_HA_OK ||
            memcmp(file_header, "OGSHAL01", 8) ||
            memcmp(file_header + 8, j->cluster, 16) ||
            nonzero(file_header + 24, 8)) return OGS_HA_ERROR;
    while (offset < st.st_size) {
        uint8_t *frame;
        size_t size;
        ogs_ha_record_t r;
        int rv;
        if (st.st_size - offset < (off_t)OGS_HA_HEADER_SIZE ||
                read_at(j->fd, header, sizeof(header), offset) != OGS_HA_OK ||
                header_size(header, &size) != OGS_HA_OK ||
                st.st_size - offset < (off_t)size) return OGS_HA_ERROR;
        frame = malloc(size);
        if (!frame) return OGS_HA_ERROR;
        rv = read_at(j->fd, frame, size, offset);
        if (rv == OGS_HA_OK) rv = ogs_ha_decode(frame, size, &r);
        if (rv == OGS_HA_OK && (memcmp(r.cluster, j->cluster, 16) ||
                    sequence == UINT64_MAX || r.sequence != sequence + 1 ||
                    r.epoch < epoch)) rv = OGS_HA_ERROR;
        if (rv == OGS_HA_OK) rv = sha256(frame, size, digest);
        if (rv == OGS_HA_OK && callback) rv = callback(&r, data);
        if (rv != OGS_HA_OK) { clear_free(frame, size); return OGS_HA_ERROR; }
        epoch = r.epoch;
        sequence = r.sequence;
        clear_free(frame, size);
        offset += (off_t)size;
    }
    j->epoch = epoch;
    j->sequence = sequence;
    j->end = st.st_size;
    memcpy(j->digest, digest, sizeof(digest));
    return OGS_HA_OK;
}

ogs_ha_journal_t *ogs_ha_journal_open(const char *path, const uint8_t cluster[16])
{
    ogs_ha_journal_t *j;
    struct stat st;
    uint8_t header[FILE_HEADER] = {0};
    char *parent, *slash;
    int parent_fd = -1, fresh = 0;
    if (!path || !cluster || !nonzero(cluster, 16)) return NULL;
    parent = strdup(path);
    if (!parent) return NULL;
    slash = strrchr(parent, '/');
    if (!slash) { free(parent); parent = strdup("."); }
    else if (slash == parent) slash[1] = '\0';
    else *slash = '\0';
    if (!parent) return NULL;
    parent_fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    free(parent);
    if (parent_fd < 0) return NULL;
    if (fstat(parent_fd, &st) || st.st_uid != geteuid() || (st.st_mode & 0077))
        goto fail_parent;
    j = calloc(1, sizeof(*j));
    if (!j) goto fail_parent;
    /* Resolve the basename relative to the directory already validated, not
     * by following the path again after the permission check. */
    slash = strrchr(path, '/');
    j->fd = openat(parent_fd, slash ? slash + 1 : path,
            O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_CREAT | O_EXCL, 0600);
    if (j->fd >= 0) fresh = 1;
    else if (errno == EEXIST)
        j->fd = openat(parent_fd, slash ? slash + 1 : path,
                O_RDWR | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (j->fd < 0) { free(j); goto fail_parent; }
    memcpy(j->cluster, cluster, 16);
    if (flock(j->fd, LOCK_EX | LOCK_NB) || fstat(j->fd, &st) ||
            !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
            st.st_nlink != 1 || (st.st_mode & 07777) != 0600) goto fail;
    if (fresh) {
        memcpy(header, "OGSHAL01", 8);
        memcpy(header + 8, cluster, 16);
        if (write_all(j->fd, header, sizeof(header)) != OGS_HA_OK ||
                fdatasync(j->fd) || fsync(parent_fd)) goto fail;
    } else if (st.st_size < FILE_HEADER ||
            read_at(j->fd, header, sizeof(header), 0) != OGS_HA_OK ||
            memcmp(header, "OGSHAL01", 8) || memcmp(header + 8, cluster, 16) ||
            nonzero(header + 24, 8)) goto fail;
    /* An unacknowledged write may have survived a process crash only in the
     * page cache. Make recovered records and the directory entry durable
     * before allowing an identical retry to receive an ACK. */
    if (scan(j, NULL, NULL) != OGS_HA_OK || fdatasync(j->fd) ||
            fsync(parent_fd)) goto fail;
    close(parent_fd);
    return j;
fail:
    ogs_ha_journal_close(j);
fail_parent:
    close(parent_fd);
    return NULL;
}

void ogs_ha_journal_close(ogs_ha_journal_t *j)
{
    if (!j) return;
    close(j->fd);
    OPENSSL_cleanse(j, sizeof(*j));
    free(j);
}

uint64_t ogs_ha_journal_sequence(const ogs_ha_journal_t *j)
{
    return j ? j->sequence : 0;
}

uint64_t ogs_ha_journal_epoch(const ogs_ha_journal_t *j)
{
    return j ? j->epoch : 0;
}

int ogs_ha_journal_append(ogs_ha_journal_t *j, const uint8_t *frame, size_t size)
{
    ogs_ha_record_t r;
    uint8_t digest[32];
    struct stat st;
    if (!j || j->poisoned || ogs_ha_decode(frame, size, &r) != OGS_HA_OK ||
            memcmp(r.cluster, j->cluster, 16) || sha256(frame, size, digest))
        return OGS_HA_ERROR;
    if (fstat(j->fd, &st) || st.st_size != j->end) {
        j->poisoned = 1;
        return OGS_HA_ERROR;
    }
    if (r.sequence == j->sequence)
        return CRYPTO_memcmp(digest, j->digest, 32) == 0 ?
            OGS_HA_DUPLICATE : OGS_HA_ERROR;
    if (size > OGS_HA_MAX_JOURNAL_SIZE - (size_t)j->end ||
            j->sequence == UINT64_MAX || r.sequence != j->sequence + 1 ||
            r.epoch < j->epoch) return OGS_HA_ERROR;
    if (write_all(j->fd, frame, size) != OGS_HA_OK || fdatasync(j->fd)) {
        j->poisoned = 1;
        return OGS_HA_ERROR;
    }
    j->epoch = r.epoch;
    j->sequence = r.sequence;
    j->end += (off_t)size;
    memcpy(j->digest, digest, sizeof(digest));
    return OGS_HA_OK;
}

int ogs_ha_journal_replay(ogs_ha_journal_t *j,
        ogs_ha_replay_fn callback, void *data)
{
    if (!j || j->poisoned || !callback) return OGS_HA_ERROR;
    if (scan(j, NULL, NULL) != OGS_HA_OK) { j->poisoned = 1; return OGS_HA_ERROR; }
    if (scan(j, callback, data) != OGS_HA_OK) { j->poisoned = 1; return OGS_HA_ERROR; }
    return OGS_HA_OK;
}

SSL_CTX *ogs_ha_tls_context(const char *ca, const char *cert, const char *key)
{
    SSL_CTX *ctx;
    if (!ca || !cert || !key) return NULL;
    ctx = SSL_CTX_new(TLS_method());
    if (!ctx) return NULL;
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) ||
            !SSL_CTX_load_verify_locations(ctx, ca, NULL) ||
            !SSL_CTX_use_certificate_chain_file(ctx, cert) ||
            !SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) ||
            !SSL_CTX_check_private_key(ctx)) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 2);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 0);
    SSL_CTX_set_options(ctx, SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_COMPRESSION);
    return ctx;
}

static int64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int wait_tls(SSL *ssl, int error, int64_t deadline)
{
    struct pollfd fd;
    int rv;
    int64_t left;
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE)
        return OGS_HA_ERROR;
    fd.fd = SSL_get_fd(ssl);
    fd.events = error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT;
    for (;;) {
        int64_t now = monotonic_ms();
        if (now < 0 || (left = deadline - now) <= 0) return OGS_HA_ERROR;
        fd.revents = 0;
        rv = poll(&fd, 1, (int)left);
        if (rv < 0 && errno == EINTR) continue;
        return rv > 0 && (fd.revents & fd.events) ? OGS_HA_OK : OGS_HA_ERROR;
    }
}

SSL *ogs_ha_tls_session(SSL_CTX *ctx, int fd, const char *peer, int server)
{
    SSL *ssl;
    int flags, rv;
    int64_t deadline = monotonic_ms();
    if (!ctx || fd < 0 || !peer || !*peer) return NULL;
    if (deadline < 0 || (flags = fcntl(fd, F_GETFL)) < 0 ||
            fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return NULL;
    deadline += OGS_HA_IO_TIMEOUT_MS;
    ssl = SSL_new(ctx);
    if (!ssl) return NULL;
    SSL_set_hostflags(ssl, X509_CHECK_FLAG_NEVER_CHECK_SUBJECT |
            X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS | X509_CHECK_FLAG_NO_WILDCARDS);
    if (!SSL_set1_host(ssl, peer) || !SSL_set_fd(ssl, fd) ||
            (!server && !SSL_set_tlsext_host_name(ssl, peer))) {
        SSL_free(ssl);
        return NULL;
    }
    do {
        ERR_clear_error();
        rv = server ? SSL_accept(ssl) : SSL_connect(ssl);
        if (rv == 1) break;
        if (wait_tls(ssl, SSL_get_error(ssl, rv), deadline) != OGS_HA_OK) {
            SSL_free(ssl);
            return NULL;
        }
    } while (1);
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        SSL_free(ssl);
        return NULL;
    }
    return ssl;
}

static int tls_io(SSL *ssl, uint8_t *p, size_t size, int writing, int64_t deadline)
{
    while (size) {
        size_t done = 0;
        int64_t now = monotonic_ms();
        if (now < 0 || now >= deadline) return OGS_HA_ERROR;
        ERR_clear_error();
        int rv = writing ? SSL_write_ex(ssl, p, size, &done) :
            SSL_read_ex(ssl, p, size, &done);
        if (rv != 1) {
            if (wait_tls(ssl, SSL_get_error(ssl, rv), deadline) != OGS_HA_OK)
                return OGS_HA_ERROR;
            continue;
        }
        if (!done) return OGS_HA_ERROR;
        p += done; size -= done;
    }
    return OGS_HA_OK;
}

static int make_ack(const uint8_t *frame, size_t size, uint8_t ack[OGS_HA_ACK_SIZE])
{
    memset(ack, 0, OGS_HA_ACK_SIZE);
    memcpy(ack, "OGHAACK1", 8);
    /* Cluster, epoch and sequence match the request in network byte order. */
    memcpy(ack + 8, frame + 8, 32);
    return sha256(frame, size, ack + 48);
}

int ogs_ha_send(SSL *ssl, const uint8_t *frame, size_t size)
{
    ogs_ha_record_t r;
    uint8_t ack[OGS_HA_ACK_SIZE], expected[OGS_HA_ACK_SIZE];
    int64_t deadline = monotonic_ms();
    if (!ssl || deadline < 0 || ogs_ha_decode(frame, size, &r) != OGS_HA_OK ||
            make_ack(frame, size, expected) != OGS_HA_OK ||
            tls_io(ssl, (uint8_t *)frame, size, 1, deadline + OGS_HA_IO_TIMEOUT_MS) != OGS_HA_OK ||
            tls_io(ssl, ack, sizeof(ack), 0, deadline + OGS_HA_IO_TIMEOUT_MS) != OGS_HA_OK ||
            CRYPTO_memcmp(ack, expected, sizeof(ack))) return OGS_HA_ERROR;
    return OGS_HA_OK;
}

int ogs_ha_receive(SSL *ssl, ogs_ha_journal_t *journal)
{
    uint8_t header[OGS_HA_HEADER_SIZE], ack[OGS_HA_ACK_SIZE], *frame;
    size_t size;
    int rv;
    int64_t deadline = monotonic_ms();
    if (deadline < 0) return OGS_HA_ERROR;
    deadline += OGS_HA_IO_TIMEOUT_MS;
    if (!ssl || !journal || tls_io(ssl, header, sizeof(header), 0, deadline) != OGS_HA_OK ||
            header_size(header, &size) != OGS_HA_OK) return OGS_HA_ERROR;
    frame = malloc(size);
    if (!frame) return OGS_HA_ERROR;
    memcpy(frame, header, sizeof(header));
    rv = tls_io(ssl, frame + sizeof(header), size - sizeof(header), 0, deadline);
    if (rv == OGS_HA_OK) rv = ogs_ha_journal_append(journal, frame, size);
    if (rv == OGS_HA_OK || rv == OGS_HA_DUPLICATE) {
        rv = make_ack(frame, size, ack);
        if (rv == OGS_HA_OK) rv = tls_io(ssl, ack, sizeof(ack), 1, deadline);
    }
    clear_free(frame, size);
    return rv;
}
