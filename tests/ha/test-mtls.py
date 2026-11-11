#!/usr/bin/env python3
"""Isolated localhost peers, ephemeral PKI and synthetic state only."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest

PEER = os.path.abspath(sys.argv[1])
sys.argv = [sys.argv[0]]


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)


class ReplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="ogs-ha-mtls-")
        cls.root = Path(cls.tmp.name)
        cls.primary = "primary.ha.example.invalid"
        cls.secondary = "secondary.ha.example.invalid"
        for ca in ("ca", "foreign-ca"):
            openssl("req", "-x509", "-newkey", "ec", "-pkeyopt",
                    "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                    "-subj", f"/CN={ca}", "-keyout", cls.root / f"{ca}.key",
                    "-out", cls.root / f"{ca}.pem")
        cls.certificate("primary", cls.primary)
        cls.certificate("secondary", cls.secondary)
        cls.certificate("wrong-name", "other.ha.example.invalid")
        cls.certificate("foreign", cls.primary, ca="foreign-ca")
        cls.certificate("no-san", cls.primary, san=False)
        cls.certificate("wildcard", "*.ha.example.invalid")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    @classmethod
    def certificate(cls, name, dns, ca="ca", san=True):
        p = cls.root
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt",
                "ec_paramgen_curve:P-256", "-nodes", "-subj", f"/CN={dns}",
                "-keyout", p / f"{name}.key", "-out", p / f"{name}.csr")
        extension = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\n"
        if san:
            extension += f"subjectAltName=DNS:{dns}\n"
        (p / f"{name}.ext").write_text(extension)
        openssl("x509", "-req", "-in", p / f"{name}.csr", "-days", "1",
                "-CA", p / f"{ca}.pem", "-CAkey", p / f"{ca}.key",
                "-CAcreateserial", "-extfile", p / f"{name}.ext",
                "-out", p / f"{name}.pem")

    def run_pair(self, journal, client_cert="primary", server_cert="secondary",
                 client_mode="one", server_mode="normal", count=1,
                 expected_server=None, expected_client=None):
        # Real TCP sockets, inherited by two independent C processes. No core
        # interfaces, IMS traffic, SSH credentials or production keys involved.
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        client = socket.create_connection(listener.getsockname(), timeout=3)
        accepted, _ = listener.accept()
        listener.close()
        children = []
        started = time.monotonic()
        try:
            def command(role, sock, certificate, peer, mode):
                p = self.root
                return [PEER, role, str(sock.fileno()), str(p / "ca.pem"),
                        str(p / f"{certificate}.pem"), str(p / f"{certificate}.key"),
                        peer, mode]
            server_args = command("server", accepted, server_cert,
                                  expected_client or self.primary, server_mode)
            # Last placeholder ensures argument counts catch malformed tests.
            server_args += [str(journal), str(count), "test-only"]
            client_args = command("client", client, client_cert,
                                  expected_server or self.secondary, client_mode)
            client_args += ["test-only"]
            children.append(subprocess.Popen(server_args, pass_fds=[accepted.fileno()],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            children.append(subprocess.Popen(client_args, pass_fds=[client.fileno()],
                                             stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            accepted.close()
            client.close()
            results = []
            for child in children:
                stdout, stderr = child.communicate(timeout=15)
                results.append((child.returncode, stdout.decode(), stderr.decode()))
                if len(results) == 1:
                    self.last_server_duration = time.monotonic() - started
            return results
        finally:
            accepted.close()
            client.close()
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate()

    def inspect(self, journal):
        return subprocess.check_output([PEER, "inspect", str(journal)], text=True, timeout=5)

    def test_ordered_replication_duplicate_large_payload_and_recovery(self):
        with tempfile.TemporaryDirectory(dir=self.root) as d:
            path = Path(d) / "journal"
            server, client = self.run_pair(path, client_mode="good", count=6)
            self.assertEqual(server[0], 0, server)
            self.assertEqual(client[0], 0, client)
            self.assertIn("sequence=5 epoch=7", self.inspect(path))
            # Independent wire-layout, payload and CRC verification.
            import struct
            import zlib
            raw = path.read_bytes()
            self.assertEqual(raw[:8], b"OGSHAL01")
            offset, sequences = 32, []
            while offset < len(raw):
                header = raw[offset:offset + 64]
                size = struct.unpack(">I", header[44:48])[0]
                frame = bytearray(raw[offset:offset + 64 + size])
                checksum = struct.unpack(">I", frame[56:60])[0]
                frame[56:60] = b"\0" * 4
                self.assertEqual(zlib.crc32(frame), checksum)
                sequences.append(struct.unpack(">Q", header[32:40])[0])
                if sequences[-1] == 2:
                    self.assertEqual(size, 1024 * 1024)
                    self.assertEqual(frame[64:], bytes(i % 251 for i in range(size)))
                offset += len(frame)
            self.assertEqual(sequences, [1, 2, 3, 4, 5])

    def test_rejects_untrusted_wrong_identity_and_cn_only_client(self):
        for cert in ("foreign", "wrong-name", "no-san", "wildcard"):
            with self.subTest(cert=cert), tempfile.TemporaryDirectory(dir=self.root) as d:
                path = Path(d) / "journal"
                server, client = self.run_pair(path, client_cert=cert)
                self.assertNotEqual(client[0], 0, client)
                self.assertNotEqual(server[0], 0, server)
                self.assertFalse(path.exists())

    def test_rejects_wrong_server_identity(self):
        with tempfile.TemporaryDirectory(dir=self.root) as d:
            path = Path(d) / "journal"
            server, client = self.run_pair(path, expected_server="wrong.ha.example.invalid")
            self.assertNotEqual(client[0], 0, client)
            self.assertFalse(path.exists())

    def test_foreign_cluster_and_gap_get_no_ack(self):
        for mode in ("foreign", "gap"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(dir=self.root) as d:
                path = Path(d) / "journal"
                server, client = self.run_pair(path, client_mode=mode)
                self.assertNotEqual(client[0], 0, client)
                self.assertNotEqual(server[0], 0, server)
                self.assertIn("sequence=0 epoch=0", self.inspect(path))

    def test_ack_loss_retry_after_receiver_restart_is_idempotent(self):
        with tempfile.TemporaryDirectory(dir=self.root) as d:
            path = Path(d) / "journal"
            server, client = self.run_pair(path, server_mode="drop-ack")
            self.assertNotEqual(client[0], 0, client)
            length = path.stat().st_size
            self.assertIn("sequence=1 epoch=7", self.inspect(path))
            server, client = self.run_pair(path)
            self.assertEqual((server[0], client[0]), (0, 0), (server, client))
            self.assertEqual(path.stat().st_size, length)

    def test_disk_sync_failure_gets_no_ack(self):
        with tempfile.TemporaryDirectory(dir=self.root) as d:
            path = Path(d) / "journal"
            server, client = self.run_pair(path, server_mode="sync-fail")
            self.assertNotEqual(client[0], 0, client)
            self.assertIn("sequence=0 epoch=0", server[1])
            # Surviving unacknowledged bytes are made durable on recovery.
            server, client = self.run_pair(path)
            self.assertEqual((server[0], client[0]), (0, 0), (server, client))
            self.assertIn("sequence=1 epoch=7", self.inspect(path))

    def test_wrong_ack_hash_is_not_accepted(self):
        with tempfile.TemporaryDirectory(dir=self.root) as d:
            server, client = self.run_pair(Path(d) / "journal", server_mode="wrong-ack")
            self.assertEqual(server[0], 0, server)
            self.assertNotEqual(client[0], 0, client)

    def test_slow_fragmented_frame_hits_overall_deadline(self):
        with tempfile.TemporaryDirectory(dir=self.root) as d:
            path = Path(d) / "journal"
            server, client = self.run_pair(path, client_mode="stall")
            self.assertNotEqual(server[0], 0, server)
            self.assertNotEqual(client[0], 0, client)
            self.assertLess(self.last_server_duration, 8)
            self.assertIn("sequence=0 epoch=0", self.inspect(path))


if __name__ == "__main__":
    unittest.main(verbosity=2)
