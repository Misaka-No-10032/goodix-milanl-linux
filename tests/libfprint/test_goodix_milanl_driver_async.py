#!/usr/bin/env python3
"""Run the built libfprint driver against a scripted, hardware-free v2 peer.

python3 -I tests/libfprint/test_goodix_milanl_driver_async.py --build-dir /path/to/libfprint/_build
"""
import argparse
import os
from pathlib import Path
import select
import shlex
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

HELLO, BEGIN, CAPTURE, VERIFY, IDENTIFY, CANCEL, SUSPEND, RESUME = range(1, 9)
OK, R_HELLO, STAGE, DONE, MATCH, NO_MATCH, RETRY, ERROR, INTERRUPTED = range(1, 10)
MAX_BLOB = 1024 * 1024
MAX_GALLERY = 16
MAX_MESSAGE = MAX_GALLERY * (MAX_BLOB + 4) + 3
ORIGINAL = b"goodix-milanl-driver-test-template"
VERIFY_UPDATE = b"goodix-milanl-driver-verify-update"
IDENTIFY_UPDATE = b"goodix-milanl-driver-identify-update"


def blob(value):
    return struct.pack("<I", len(value)) + value


def match(index=0xffff, update=None):
    return struct.pack("<BHB", MATCH, index, update is not None) + (
        blob(update) if update is not None else b""
    )


def read_exact(conn, length):
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            assert not data, "driver sent a truncated frame"
            return None
        data.extend(chunk)
    return bytes(data)


class Peer:
    def __init__(self, path, case, malformed=None):
        self.path = path
        self.case = case
        self.malformed = malformed
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.stopping = threading.Event()
        self.error = None
        self.connections = 0
        self.requests = []
        self.captures = 0
        self.verifies = 0
        self.identifies = 0
        self.blocked_eofs = 0
        self.suspends = 0
        self.resumes = 0
        self.begins = 0
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def stop(self):
        self.stopping.set()
        self.thread.join(5)
        self.listener.close()
        assert not self.thread.is_alive(), "test peer did not stop"
        if self.error:
            raise self.error

    def wait_for_cancel(self, conn):
        # True cancellation remains EOF, never an in-flight CANCEL opcode.
        assert conn.recv(1) == b"", "driver pipelined a command instead of closing"
        self.blocked_eofs += 1

    def serve(self):
        try:
            while not self.stopping.is_set():
                try:
                    conn, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(5)  # Test watchdog, never a driver/human deadline.
                    self.connections += 1
                    self.session(conn)
        except BaseException as exc:
            self.error = exc

    def request(self, conn):
        header = read_exact(conn, 4)
        if header is None:
            return None
        length, = struct.unpack("<I", header)
        assert 0 < length <= MAX_MESSAGE
        first = read_exact(conn, 1)
        assert first is not None
        if self.case == "suspend-write" and first[0] == IDENTIFY and not self.suspends:
            # A 1 MiB request exceeds the socket send buffer: suspend arrives
            # while the original write is still pending, before we drain it.
            time.sleep(0.25)
        rest = read_exact(conn, length - 1)
        assert rest is not None
        request = first + rest
        self.requests.append((self.connections, first[0], request))
        return request

    def respond(self, conn, response):
        frame = struct.pack("<I", len(response)) + response
        if self.case in ("delay", "suspend-enroll-final", "suspend-match"):
            for fragment in (frame[:1], frame[1:3], frame[3:5], frame[5:]):
                conn.sendall(fragment)
                time.sleep(0.002)
        else:
            conn.sendall(frame)

    def suspend(self, conn, response=None):
        if response is not None:
            assert self.request(conn) == bytes([SUSPEND]), "only SUSPEND may interrupt a request"
            self.respond(conn, response)
        self.suspends += 1
        if self.case == "cancel-suspend":
            self.wait_for_cancel(conn)
            return False
        if self.case in ("suspend", "suspend-identify"):
            time.sleep(0.08)
        self.respond(conn, bytes([OK]) + (b"trailing" if self.case == "suspend-error" else b""))
        return True

    def session(self, conn):
        stage = 0
        greeted = False
        paused = False
        late_failure = False
        while True:
            request = self.request(conn)
            if request is None:
                return
            op = request[0]
            assert greeted or op == HELLO, "reconnection omitted HELLO"
            assert not paused or op == RESUME, "operation sent before RESUME"
            if op == HELLO:
                assert request == struct.pack("<BI", HELLO, 2)
                greeted = True
                if self.case == "cancel-open" and self.connections == 1:
                    self.wait_for_cancel(conn)
                    return
                if self.case == "delay" or (self.case == "suspend-hello" and self.connections == 2):
                    time.sleep(0.2)
                response = struct.pack("<BIHI", R_HELLO, 2, 12, 3)
                if self.case == "malformed-hello" and self.connections == 1:
                    response += b"trailing"
            elif op == BEGIN:
                assert request == bytes([BEGIN])
                self.begins += 1
                stage = 0
                if self.case in ("suspend-begin", "suspend-before") and not self.suspends:
                    response = bytes([INTERRUPTED if self.case == "suspend-begin" else OK])
                    if not self.suspend(conn, response):
                        return
                    paused = True
                    continue
                response = bytes([OK])
            elif op == CAPTURE:
                assert request == bytes([CAPTURE])
                self.captures += 1
                if self.case == "cancel-enroll" and self.captures == 1:
                    self.wait_for_cancel(conn)
                    return
                stop_at = {"suspend-enroll": 3, "suspend-enroll-late": 4,
                           "suspend-enroll-stage": 2, "suspend-enroll-final": 12,
                           "suspend-enroll-reset": 12}.get(self.case)
                if self.captures == stop_at and not self.suspends:
                    response = bytes([INTERRUPTED])
                    if self.case == "suspend-enroll-stage":
                        stage += 1
                        response = struct.pack("<BH", STAGE, stage)
                    elif self.case == "suspend-enroll-final":
                        stage += 1
                        response = bytes([DONE]) + blob(ORIGINAL)
                    elif self.case == "suspend-enroll-reset":
                        # Engine12 completed count 12 but its response was
                        # interrupted. OEM Update resets that host count to 0.
                        stage = 0
                    if not self.suspend(conn, response):
                        return
                    paused = True
                    continue
                if self.case == "suspend-enroll-late" and self.resumes and self.begins == 1 and not late_failure:
                    late_failure = True
                    response = bytes([ERROR, 1])  # OEM Engine11 -3 -> E_FAIL.
                elif self.case == "malformed-enroll" and self.captures == 1:
                    response = struct.pack("<BH", STAGE, 1) + b"trailing"
                elif self.case == "roundtrip" and self.captures == 1:
                    response = bytes([RETRY, 3])
                else:
                    stage += 1
                    response = struct.pack("<BH", STAGE, stage) if stage < 12 else bytes([DONE]) + blob(ORIGINAL)
            elif op in (VERIFY, IDENTIFY):
                offset = 1
                count = 1
                if op == IDENTIFY:
                    count, = struct.unpack_from("<H", request, offset)
                    offset += 2
                    assert count <= MAX_GALLERY
                    if self.case == "max-gallery":
                        assert count == MAX_GALLERY and len(request) == MAX_MESSAGE
                for _ in range(count):
                    size, = struct.unpack_from("<I", request, offset)
                    assert 0 < size <= MAX_BLOB
                    offset += 4
                    if self.case in ("suspend-write", "max-gallery") and op == IDENTIFY:
                        expected = MAX_BLOB if self.case == "max-gallery" else 65536
                        assert request[offset:offset + size] == b"w" * expected
                    offset += size
                assert offset == len(request)
                if op == VERIFY:
                    self.verifies += 1
                    nth = self.verifies
                else:
                    self.identifies += 1
                    nth = self.identifies
                index = 0xffff if op == VERIFY else 1
                if nth == 1 and self.case == "cancel":
                    self.wait_for_cancel(conn)
                    return
                if nth == 1 and self.case in (
                    "suspend", "suspend-identify", "cancel-paused", "cancel-suspend",
                    "cancel-resume", "suspend-error", "resume-error", "suspend-match",
                    "suspend-identify-match", "cancel-saved", "suspend-write",
                ) and not self.suspends:
                    response = bytes([INTERRUPTED])
                    if self.case in ("suspend-match", "suspend-identify-match", "cancel-saved"):
                        response = match(index, VERIFY_UPDATE if op == VERIFY else IDENTIFY_UPDATE)
                    if not self.suspend(conn, response):
                        return
                    paused = True
                    continue
                if self.case == "delay":
                    time.sleep(0.25)
                if nth == 1 and ((self.case == "malformed" and op == VERIFY) or
                                 (self.case == "malformed-identify" and op == IDENTIFY)):
                    response = self.malformed
                elif self.case == "truncated-frame" and nth == 1:
                    conn.sendall(struct.pack("<I", 8) + bytes([MATCH, 0xff]))
                    return
                elif self.case == "roundtrip":
                    response = match(index, VERIFY_UPDATE if op == VERIFY else IDENTIFY_UPDATE)
                elif self.case == "no-match":
                    response = bytes([NO_MATCH])
                elif self.case == "retry":
                    response = bytes([RETRY, 2])
                else:
                    response = match(index)
            elif op == SUSPEND:
                assert request == bytes([SUSPEND])
                if not self.suspend(conn):
                    return
                paused = True
                continue
            elif op == RESUME:
                assert request == bytes([RESUME]) and paused
                self.resumes += 1
                paused = False
                if self.case == "cancel-resume":
                    self.wait_for_cancel(conn)
                    return
                response = bytes([OK]) + (b"trailing" if self.case == "resume-error" else b"")
            else:
                raise AssertionError(f"unexpected opcode {op}")

            assert not select.select([conn], [], [], 0)[0], "unexpected pipelined request"
            self.respond(conn, response)


class DriverAsyncTest(unittest.TestCase):
    binary = None
    build = None

    def exercise(self, case, malformed=None):
        with tempfile.TemporaryDirectory(prefix="goodix-milanl-async-test-") as temp:
            peer = Peer(Path(temp) / "engine.sock", case, malformed)
            try:
                env = dict(os.environ, GOODIX_MILANL_ENGINE=str(peer.path),
                           LD_LIBRARY_PATH=str(self.build / "libfprint"), G_DEBUG="fatal-warnings")
                result = subprocess.run([str(self.binary), case], env=env,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                peer.stop()
            ops = [op for _, op, _ in peer.requests]
            self.assertNotIn(CANCEL, ops)
            if case == "invalid-gallery":
                self.assertNotIn(IDENTIFY, ops)
            if case in ("cancel", "cancel-open", "cancel-enroll"):
                self.assertEqual(peer.blocked_eofs, 1)
                self.assertGreaterEqual(peer.connections, 2)
            if case.startswith("suspend") or case in ("cancel-resume", "resume-error", "cancel-saved", "cancel-paused"):
                self.assertIn(SUSPEND, ops)
                if case not in ("suspend-error", "cancel-saved", "cancel-paused"):
                    self.assertIn(RESUME, ops)
                    power_connections = {number for number, op, _ in peer.requests if op in (SUSPEND, RESUME)}
                    self.assertEqual(len(power_connections), 1, "suspend/resume must share one engine session")
            if case in ("suspend", "suspend-identify", "suspend-enroll", "suspend-enroll-stage",
                        "suspend-enroll-final", "suspend-enroll-reset", "suspend-match",
                        "suspend-identify-match", "suspend-begin", "suspend-before", "suspend-write"):
                self.assertEqual(peer.connections, 1)
                self.assertEqual(peer.suspends, 1)
                self.assertEqual(peer.resumes, 1)
            if case.startswith("suspend-enroll") or case in ("suspend-begin", "suspend-before", "suspend-connect", "suspend-hello"):
                self.assertEqual(peer.begins, 2 if case in ("suspend-begin", "suspend-enroll-late") else 1)
            if case in ("suspend-enroll-final", "suspend-enroll-stage"):
                self.assertEqual(peer.captures, 12, "completed responses must not be sampled again")
            if case == "suspend-enroll-reset":
                self.assertEqual(peer.captures, 24)
            if case == "suspend-match":
                self.assertEqual(peer.verifies, 2)  # Saved result, then healthy reuse.
            if case == "suspend-identify-match":
                self.assertEqual(peer.identifies, 1)
            if case == "suspend-write":
                self.assertEqual(peer.identifies, 2)
            if case in ("cancel-before", "cancel-needed"):
                self.assertEqual(peer.verifies, 1)
            if case == "cancel-progress":
                self.assertEqual(peer.captures, 13)
            if case == "cancel-final":
                self.assertEqual(peer.captures, 24)
            if case in ("malformed", "malformed-identify", "truncated-frame"):
                self.assertGreaterEqual(peer.connections, 2)

    def test_roundtrip_adaptation_and_progress(self):
        self.exercise("roundtrip")

    def test_main_loop_during_delayed_open_and_capture(self):
        self.exercise("delay")

    def test_cancellation_and_reuse(self):
        for case in ("cancel-open", "cancel-enroll", "cancel", "cancel-progress", "cancel-final",
                     "cancel-before", "cancel-needed", "cancel-report"):
            with self.subTest(case=case):
                self.exercise(case)

    def test_suspend_resume_and_cancellation(self):
        for case in ("suspend", "suspend-identify", "cancel-paused", "cancel-saved",
                     "cancel-suspend", "cancel-resume", "suspend-error", "resume-error"):
            with self.subTest(case=case):
                self.exercise(case)

    def test_oem_enrollment_suspend_contract(self):
        for case in ("suspend-enroll", "suspend-enroll-late", "suspend-enroll-stage",
                     "suspend-enroll-final", "suspend-enroll-reset", "suspend-begin"):
            with self.subTest(case=case):
                self.exercise(case)

    def test_suspend_before_capture_and_during_request_write(self):
        for case in ("suspend-before", "suspend-connect", "suspend-hello", "suspend-write"):
            with self.subTest(case=case):
                self.exercise(case)

    def test_completed_match_is_saved_until_resume(self):
        self.exercise("suspend-match")
        self.exercise("suspend-identify-match")

    def test_gallery_bounds_are_not_filtered_or_truncated(self):
        self.exercise("invalid-gallery")
        self.exercise("max-gallery")

    def test_retry_and_no_match(self):
        self.exercise("retry")
        self.exercise("no-match")

    def test_malformed_match(self):
        bad = {
            "bare": bytes([MATCH]),
            "short-index": bytes([MATCH, 0xff]),
            "missing-update-flag": struct.pack("<BH", MATCH, 0xffff),
            "invalid-update-flag": struct.pack("<BHB", MATCH, 0xffff, 2),
            "wrong-verify-index": match(0),
            "short-blob-length": struct.pack("<BHB", MATCH, 0xffff, 1) + b"\x01",
            "short-blob": struct.pack("<BHBI", MATCH, 0xffff, 1, 8) + b"short",
            "empty-update": match(update=b""),
            "oversized-update": struct.pack("<BHBI", MATCH, 0xffff, 1, MAX_BLOB + 1),
            "trailing": match() + b"trailing",
            "trailing-update": match(update=VERIFY_UPDATE) + b"trailing",
            "no-match-trailing": bytes([NO_MATCH, 0]),
            "retry-truncated": bytes([RETRY]),
            "retry-invalid": bytes([RETRY, 0]),
            "retry-trailing": bytes([RETRY, 1, 0]),
            "error-truncated": bytes([ERROR]),
            "error-invalid": bytes([ERROR, 0]),
            "error-trailing": bytes([ERROR, 1, 0]),
            "unsolicited-interrupted": bytes([INTERRUPTED]),
            "interrupted-trailing": bytes([INTERRUPTED, 0]),
        }
        for name, response in bad.items():
            with self.subTest(response=name):
                self.exercise("malformed", response)
        self.exercise("malformed-identify", match(2, IDENTIFY_UPDATE))
        self.exercise("malformed-identify", match(1, IDENTIFY_UPDATE) + b"trailing")

    def test_other_malformed_responses(self):
        self.exercise("malformed-hello")
        self.exercise("malformed-enroll")
        self.exercise("truncated-frame")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    args, remaining = parser.parse_known_args()
    build = args.build_dir.resolve()
    env = dict(os.environ, PKG_CONFIG_PATH=str(build / "meson-uninstalled"))
    flags = shlex.split(subprocess.check_output(
        ["pkg-config", "--cflags", "--libs", "libfprint-2-uninstalled"], env=env, text=True))
    with tempfile.TemporaryDirectory(prefix="goodix-milanl-async-client-") as temp:
        binary = Path(temp) / "client"
        subprocess.run(["cc", "-Wall", "-Wextra", "-Wno-unused-parameter", "-g",
                        str(Path(__file__).with_name("goodix_milanl_driver_async_client.c")),
                        "-o", str(binary), *flags], check=True)
        DriverAsyncTest.binary = binary
        DriverAsyncTest.build = build
        unittest.main(argv=[__file__, *remaining])


if __name__ == "__main__":
    main()
