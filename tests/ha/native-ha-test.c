/* Copyright (C) 2026 Open5GS contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later */
#define _POSIX_C_SOURCE 200809L
#include "ogs-ha.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); exit(1); \
} } while (0)

int __real_fdatasync(int fd);
ssize_t __real_write(int fd, const void *p, size_t n);
int __wrap_fdatasync(int fd);
ssize_t __wrap_write(int fd, const void *p, size_t n);
static int fail_sync, fail_write;

int __wrap_fdatasync(int fd)
{
    if (fail_sync) { fail_sync = 0; errno = EIO; return -1; }
    return __real_fdatasync(fd);
}

ssize_t __wrap_write(int fd, const void *p, size_t n)
{
    if (fail_write == 2) { fail_write = 1; return __real_write(fd, p, n > 8 ? 8 : n); }
    if (fail_write == 1) { fail_write = 0; errno = ENOSPC; return -1; }
    return __real_write(fd, p, n);
}

static uint8_t cluster[16] = {1, 2, 3};

static uint8_t *record(uint64_t epoch, uint64_t seq, uint16_t kind,
        const char *payload, size_t *size)
{
    ogs_ha_record_t r = {0};
    uint8_t *frame = NULL;
    memcpy(r.cluster, cluster, 16);
    r.epoch = epoch; r.sequence = seq;
    r.kind = kind; r.component = OGS_HA_MME;
    r.payload = (const uint8_t *)payload;
    r.payload_size = payload ? (uint32_t)strlen(payload) : 0;
    CHECK(ogs_ha_encode(&r, &frame, size) == OGS_HA_OK);
    return frame;
}

static off_t file_size(const char *path)
{
    struct stat st;
    CHECK(stat(path, &st) == 0);
    return st.st_size;
}

static void change_byte(const char *path, off_t offset)
{
    int fd = open(path, O_RDWR);
    uint8_t value;
    CHECK(fd >= 0 && pread(fd, &value, 1, offset) == 1);
    value ^= 1;
    CHECK(pwrite(fd, &value, 1, offset) == 1);
    CHECK(close(fd) == 0);
}

static int count_record(const ogs_ha_record_t *r, void *data)
{
    unsigned *count = data;
    CHECK(r->sequence == (uint64_t)*count + 1);
    (*count)++;
    return OGS_HA_OK;
}

static void wire_tests(void)
{
    size_t size, i;
    uint8_t *frame = record(UINT64_C(0x0102030405060708), 1,
            OGS_HA_UPSERT, "TEST-only", &size);
    ogs_ha_record_t r, sentinel;
    CHECK(size == 73 && frame[24] == 1 && frame[31] == 8 && frame[39] == 1);
    CHECK(ogs_ha_decode(frame, size, &r) == OGS_HA_OK);
    CHECK(r.epoch == UINT64_C(0x0102030405060708) && r.sequence == 1);
    CHECK(r.payload_size == 9 && !memcmp(r.payload, "TEST-only", 9));
    memset(&sentinel, 0, sizeof(sentinel));
    r = sentinel;
    for (i = 0; i < size; i++) {
        frame[i] ^= 1;
        CHECK(ogs_ha_decode(frame, size, &r) == OGS_HA_ERROR);
        CHECK(!memcmp(&r, &sentinel, sizeof(r)));
        frame[i] ^= 1;
    }
    for (i = 0; i < size; i++) CHECK(ogs_ha_decode(frame, i, &r) == OGS_HA_ERROR);
    CHECK(ogs_ha_decode(frame, size + 1, &r) == OGS_HA_ERROR);
    free(frame);
    frame = record(1, 1, OGS_HA_BARRIER, NULL, &size);
    CHECK(ogs_ha_decode(frame, size, &r) == OGS_HA_OK && r.payload_size == 0);
    free(frame);
    memcpy(r.cluster, cluster, 16);
    r.epoch = 0;
    CHECK(ogs_ha_encode(&r, &frame, &size) == OGS_HA_ERROR);
    r.epoch = 1; r.sequence = 0;
    CHECK(ogs_ha_encode(&r, &frame, &size) == OGS_HA_ERROR);
    r.sequence = 1; r.payload_size = OGS_HA_MAX_PAYLOAD + 1;
    CHECK(ogs_ha_encode(&r, &frame, &size) == OGS_HA_ERROR);
    r.payload_size = 1; r.payload = NULL;
    CHECK(ogs_ha_encode(&r, &frame, &size) == OGS_HA_ERROR);
    puts("PASS wire format, byte corruption, truncation and input bounds");
}

static void ordering_tests(const char *path)
{
    ogs_ha_journal_t *j = ogs_ha_journal_open(path, cluster), *other;
    uint8_t *one, *two, *next, *conflict, *foreign;
    size_t n1, n2, nn, nc, nf;
    off_t length;
    unsigned count = 0;
    CHECK(j && ogs_ha_journal_sequence(j) == 0);
    other = ogs_ha_journal_open(path, cluster);
    CHECK(!other);
    one = record(2, 1, OGS_HA_UPSERT, "UE-test/IP-test/NAS-count=42", &n1);
    two = record(3, 2, OGS_HA_DELETE, "UE-test", &n2);
    CHECK(ogs_ha_journal_append(j, two, n2) == OGS_HA_ERROR);
    CHECK(ogs_ha_journal_append(j, one, n1) == OGS_HA_OK);
    length = file_size(path);
    CHECK(ogs_ha_journal_append(j, one, n1) == OGS_HA_DUPLICATE);
    CHECK(file_size(path) == length);
    conflict = record(2, 1, OGS_HA_UPSERT, "NAS-count=41", &nc);
    CHECK(ogs_ha_journal_append(j, conflict, nc) == OGS_HA_ERROR);
    free(conflict);
    CHECK(ogs_ha_journal_append(j, two, n2) == OGS_HA_OK);
    CHECK(ogs_ha_journal_append(j, one, n1) == OGS_HA_ERROR);
    next = record(2, 3, OGS_HA_BARRIER, NULL, &nn);
    CHECK(ogs_ha_journal_append(j, next, nn) == OGS_HA_ERROR);
    free(next);
    cluster[15] = 1;
    foreign = record(3, 3, OGS_HA_BARRIER, NULL, &nf);
    cluster[15] = 0;
    CHECK(ogs_ha_journal_append(j, foreign, nf) == OGS_HA_ERROR);
    free(foreign);
    CHECK(ogs_ha_journal_sequence(j) == 2 && ogs_ha_journal_epoch(j) == 3);
    ogs_ha_journal_close(j);
    j = ogs_ha_journal_open(path, cluster);
    CHECK(j && ogs_ha_journal_sequence(j) == 2 && ogs_ha_journal_epoch(j) == 3);
    CHECK(ogs_ha_journal_append(j, two, n2) == OGS_HA_DUPLICATE);
    CHECK(ogs_ha_journal_replay(j, count_record, &count) == OGS_HA_OK && count == 2);
    /* A corrupt suffix must not produce even one replay callback. */
    change_byte(path, file_size(path) - 1);
    count = 0;
    CHECK(ogs_ha_journal_replay(j, count_record, &count) == OGS_HA_ERROR && count == 0);
    CHECK(ogs_ha_journal_append(j, two, n2) == OGS_HA_ERROR);
    ogs_ha_journal_close(j);
    length = file_size(path);
    CHECK(!ogs_ha_journal_open(path, cluster) && file_size(path) == length);
    CHECK(unlink(path) == 0);
    free(one); free(two);
    puts("PASS exclusive ownership, sequence/epoch ordering, exact retry, recovery and atomic validation");
}

static void file_tests(const char *path, const char *dir)
{
    ogs_ha_journal_t *j;
    char link_path[512];
    uint8_t *frame;
    size_t size, cut;
    int fd;
    struct stat st;
    snprintf(link_path, sizeof(link_path), "%s/link", dir);
    j = ogs_ha_journal_open(path, cluster);
    CHECK(j && stat(path, &st) == 0 && (st.st_mode & 0777) == 0600);
    ogs_ha_journal_close(j);
    CHECK(chmod(path, 0640) == 0 && !ogs_ha_journal_open(path, cluster));
    CHECK(chmod(path, 0600) == 0);
    CHECK(symlink(path, link_path) == 0 && !ogs_ha_journal_open(link_path, cluster));
    CHECK(unlink(link_path) == 0);
    CHECK(link(path, link_path) == 0 && !ogs_ha_journal_open(path, cluster));
    CHECK(unlink(link_path) == 0);
    cluster[15] = 1;
    CHECK(!ogs_ha_journal_open(path, cluster));
    cluster[15] = 0;
    CHECK(chmod(dir, 0755) == 0 && !ogs_ha_journal_open(path, cluster));
    CHECK(chmod(dir, 0700) == 0);
    CHECK(unlink(path) == 0);
    frame = record(1, 1, OGS_HA_UPSERT, "synthetic", &size);
    for (cut = 1; cut < size; cut++) {
        off_t length;
        j = ogs_ha_journal_open(path, cluster);
        CHECK(j);
        ogs_ha_journal_close(j);
        fd = open(path, O_WRONLY | O_APPEND);
        CHECK(fd >= 0 && write(fd, frame, cut) == (ssize_t)cut && close(fd) == 0);
        length = file_size(path);
        CHECK(!ogs_ha_journal_open(path, cluster) && file_size(path) == length);
        CHECK(unlink(path) == 0);
    }
    free(frame);
    j = ogs_ha_journal_open(path, cluster);
    CHECK(j);
    fd = open(path, O_WRONLY | O_TRUNC);
    CHECK(fd >= 0 && close(fd) == 0);
    { unsigned count = 0; CHECK(ogs_ha_journal_replay(j, count_record, &count) == OGS_HA_ERROR); }
    ogs_ha_journal_close(j);
    CHECK(!ogs_ha_journal_open(path, cluster) && file_size(path) == 0);
    CHECK(unlink(path) == 0);
    puts("PASS permissions, foreign cluster, symlink/hardlink refusal and every torn-record boundary");
}

static void io_tests(const char *path)
{
    ogs_ha_journal_t *j;
    uint8_t *frame;
    size_t size;
    frame = record(1, 1, OGS_HA_UPSERT, "synthetic", &size);
    j = ogs_ha_journal_open(path, cluster);
    CHECK(j);
    fail_sync = 1;
    CHECK(ogs_ha_journal_append(j, frame, size) == OGS_HA_ERROR);
    CHECK(ogs_ha_journal_sequence(j) == 0);
    CHECK(ogs_ha_journal_append(j, frame, size) == OGS_HA_ERROR);
    ogs_ha_journal_close(j);
    /* The record may exist, but recovery must sync it before retry/ACK. */
    fail_sync = 1;
    CHECK(!ogs_ha_journal_open(path, cluster));
    j = ogs_ha_journal_open(path, cluster);
    CHECK(j && ogs_ha_journal_append(j, frame, size) == OGS_HA_DUPLICATE);
    ogs_ha_journal_close(j);
    CHECK(unlink(path) == 0);
    j = ogs_ha_journal_open(path, cluster);
    CHECK(j);
    fail_write = 2;
    CHECK(ogs_ha_journal_append(j, frame, size) == OGS_HA_ERROR);
    CHECK(ogs_ha_journal_append(j, frame, size) == OGS_HA_ERROR);
    ogs_ha_journal_close(j);
    CHECK(file_size(path) == 40 && !ogs_ha_journal_open(path, cluster));
    CHECK(unlink(path) == 0);
    free(frame);
    puts("PASS fsync failure, short-write/ENOSPC, poisoned handles and durable recovery before retry");
}

int main(void)
{
    char dir[] = "/tmp/ogs-ha-test-XXXXXX", path[512];
    CHECK(mkdtemp(dir));
    snprintf(path, sizeof(path), "%s/journal", dir);
    wire_tests(); ordering_tests(path); file_tests(path, dir); io_tests(path);
    CHECK(rmdir(dir) == 0);
    puts("All native HA journal tests passed (synthetic state only; no NF continuity claim).");
    return 0;
}
