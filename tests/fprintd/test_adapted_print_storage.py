#!/usr/bin/env python3
"""Exercise real fprintd/libfprint with a private bus and scripted v2 engine."""
import argparse
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

import gi

gi.require_version("FPrint", "2.0")
from gi.repository import FPrint, Gio, GLib

HELLO, BEGIN, CAPTURE, VERIFY, IDENTIFY = range(1, 6)
OK, R_HELLO, STAGE, DONE, MATCH, NO_MATCH, RETRY = range(1, 8)
BUS = "net.reactivated.Fprint"
DEVICE = BUS + ".Device"
MANAGER = BUS + ".Manager"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
POLKIT = "org.freedesktop.PolicyKit1"
RIGHT = b"fprintd-test-right-index"
LEFT = b"fprintd-test-left-index"
UPDATED = b"fprintd-test-adapted-template"
RECOVERED = b"fprintd-test-recovered-template"
USERNAME = "milanl-adaptation-test"


def blob(value):
    return struct.pack("<I", len(value)) + value


def match(index=0xffff, update=None):
    return struct.pack("<BHB", MATCH, index, update is not None) + (
        blob(update) if update is not None else b""
    )


def read_exact(conn, length):
    data = bytearray()
    while len(data) < length:
        part = conn.recv(length - len(data))
        if not part:
            assert not data, "truncated request"
            return None
        data.extend(part)
    return bytes(data)


class Engine:
    def __init__(self, path):
        self.path = path
        self.enrolling = None
        self.requests = queue.Queue()
        self.replies = queue.Queue()
        self.error = None
        self.cancelled = 0
        self.stopping = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.bind(str(path))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def close(self):
        self.stopping.set()
        self.replies.put(None)
        self.thread.join(5)
        self.listener.close()
        assert not self.thread.is_alive(), "scripted engine did not stop"
        if self.error:
            raise self.error

    def serve(self):
        try:
            while not self.stopping.is_set():
                try:
                    conn, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(5)  # Synthetic test watchdog, not a human deadline.
                    self.session(conn)
        except BaseException as error:
            self.error = error

    def session(self, conn):
        greeted = False
        stage = 0
        while True:
            header = read_exact(conn, 4)
            if header is None:
                return
            size, = struct.unpack("<I", header)
            assert 0 < size <= 16 * (1024 * 1024 + 4) + 3
            request = read_exact(conn, size)
            assert request is not None
            op = request[0]
            assert greeted or op == HELLO
            if op == HELLO:
                assert request == struct.pack("<BI", HELLO, 2)
                greeted = True
                response = struct.pack("<BIHI", R_HELLO, 2, 12, 3)
            elif op == BEGIN:
                assert self.enrolling is not None
                stage = 0
                response = bytes([OK])
            elif op == CAPTURE:
                stage += 1
                if stage < 12:
                    response = struct.pack("<BH", STAGE, stage)
                else:
                    response = bytes([DONE]) + blob(self.enrolling)
                    self.enrolling = None
            elif op in (VERIFY, IDENTIFY):
                offset, count = 1, 1
                if op == IDENTIFY:
                    count, = struct.unpack_from("<H", request, offset)
                    offset += 2
                prints = []
                for _ in range(count):
                    length, = struct.unpack_from("<I", request, offset)
                    offset += 4
                    prints.append(request[offset:offset + length])
                    offset += length
                assert offset == len(request)
                if self.enrolling is not None:
                    # fprintd checks for duplicates before every enrollment.
                    assert op == IDENTIFY
                    response = bytes([NO_MATCH])
                else:
                    self.requests.put((op, prints))
                    response = self.replies.get(timeout=5)
                    if response is None:
                        assert conn.recv(1) == b"", "cancel must close, not pipeline"
                        self.cancelled += 1
                        return
            else:
                raise AssertionError(f"unexpected opcode {op}")
            conn.sendall(blob(response))


def print_data(serialized):
    print_ = FPrint.Print.deserialize(serialized)
    date = print_.get_enroll_date()
    metadata = (
        print_.get_username(), print_.get_finger(), print_.get_description(),
        date.get_julian() if date else None, print_.get_driver(),
        print_.get_device_id(), print_.get_device_stored(),
    )
    return bytes(print_.get_property("fpi-data").unpack()), metadata


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        process.wait(timeout=5)


class AdaptedPrintStorageTest(unittest.TestCase):
    daemon_binary = None
    libfprint_libdir = None

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="milanl-fprintd-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = self.root / "state"
        self.state.mkdir()
        self.log_path = self.root / "fprintd.log"
        self.daemon = None
        self.verify_events = []
        self.enroll_events = []
        self.available = False
        self.context = GLib.MainContext.default()

        # No service activation directories: neither the host polkit nor logind
        # can be started on this bus. No host system bus connection is made.
        bus_config = self.root / "bus.conf"
        bus_config.write_text(f'''<busconfig>
  <type>system</type><listen>unix:tmpdir={self.root}</listen><auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/><allow own="*"/>
    <allow send_destination="*"/><allow receive_sender="*"/>
  </policy>
</busconfig>''')
        bus = subprocess.Popen(
            ["dbus-daemon", "--nofork", "--print-address=1",
             "--config-file=" + str(bus_config)], stdout=subprocess.PIPE, text=True)
        self.addCleanup(bus.stdout.close)
        self.addCleanup(stop_process, bus)
        address = bus.stdout.readline().strip()
        self.assertTrue(address.startswith("unix:"), address)
        self.connection = Gio.DBusConnection.new_for_address_sync(
            address, Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT |
            Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION, None, None)
        self.addCleanup(self.connection.close_sync, None)
        policy_xml = '''<node><interface name="org.freedesktop.PolicyKit1.Authority">
  <method name="CheckAuthorization">
    <arg type="(sa{sv})" direction="in"/><arg type="s" direction="in"/>
    <arg type="a{ss}" direction="in"/><arg type="u" direction="in"/>
    <arg type="s" direction="in"/><arg type="(bba{ss})" direction="out"/>
  </method>
</interface></node>'''
        self.policy_info = Gio.DBusNodeInfo.new_for_xml(policy_xml)
        registration = self.connection.register_object(
            "/org/freedesktop/PolicyKit1/Authority", self.policy_info.interfaces[0],
            self.authorize, None, None)
        self.addCleanup(self.connection.unregister_object, registration)
        self.connection.call_sync(
            "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
            "RequestName", GLib.Variant("(su)", (POLKIT, 0)),
            GLib.VariantType.new("(u)"), Gio.DBusCallFlags.NONE, 5000, None)
        watcher = Gio.bus_watch_name_on_connection(
            self.connection, BUS, Gio.BusNameWatcherFlags.NONE,
            lambda *args: setattr(self, "available", True),
            lambda *args: setattr(self, "available", False))
        self.addCleanup(Gio.bus_unwatch_name, watcher)

        self.engine = Engine(self.root / "engine.sock")
        self.addCleanup(self.engine.close)
        log = self.log_path.open("w")
        self.addCleanup(log.close)
        env = dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS=address,
                   STATE_DIRECTORY=str(self.state), RUNTIME_DIRECTORY=str(self.root),
                   GOODIX_MILANL_ENGINE=str(self.engine.path),
                   FP_DRIVERS_ALLOWLIST="goodix_milanl", FP_DRIVERS_WHITELIST="goodix_milanl",
                   LD_LIBRARY_PATH=str(self.libfprint_libdir),
                   G_DEBUG="fatal-criticals", G_MESSAGES_DEBUG="all")
        self.daemon = subprocess.Popen([str(self.daemon_binary), "--no-timeout"],
                                       env=env, stdout=log, stderr=subprocess.STDOUT)
        self.addCleanup(stop_process, self.daemon)
        self.wait_until(lambda: self.available)
        self.device_path, = self.call("GetDefaultDevice", path=MANAGER_PATH,
                                      interface=MANAGER)
        subscription = self.connection.signal_subscribe(
            BUS, DEVICE, None, self.device_path, None, Gio.DBusSignalFlags.NONE,
            self.on_signal, None)
        self.addCleanup(self.connection.signal_unsubscribe, subscription)
        self.call("Claim", "(s)", (USERNAME,))
        self.right_path = self.enroll("right-index-finger", RIGHT)

    def authorize(self, connection, sender, path, interface, method, parameters, invocation):
        self.assertEqual(method, "CheckAuthorization")
        invocation.return_value(GLib.Variant("((bba{ss}))", ((True, False, {}),)))

    def on_signal(self, connection, sender, path, interface, signal, parameters, data):
        if signal == "VerifyStatus":
            # Capture disk content when the authentication signal arrives,
            # rather than only inspecting it after VerifyStop.
            self.verify_events.append((*parameters.unpack(), self.snapshot()))
        elif signal == "EnrollStatus":
            self.enroll_events.append(parameters.unpack())

    def snapshot(self):
        return {path: path.read_bytes() for path in self.state.rglob("*") if path.is_file()}

    def wait_until(self, condition):
        deadline = time.monotonic() + 5
        while not condition():
            if self.engine.error:
                raise self.engine.error
            if self.daemon.poll() is not None:
                self.fail(self.log_path.read_text())
            if time.monotonic() >= deadline:
                self.fail("synthetic test timed out\n" + self.log_path.read_text())
            while self.context.pending():
                self.context.iteration(False)
            time.sleep(0.001)

    def call(self, method, signature="()", args=(), path=None, interface=DEVICE):
        result = []

        def done(connection, task, data):
            try:
                result.append(connection.call_finish(task))
            except GLib.Error as error:
                result.append(error)

        # Pump GLib while waiting, so the private polkit service can answer the
        # daemon's synchronous authorization request on this same test thread.
        self.connection.call(BUS, path or self.device_path, interface, method,
                             GLib.Variant(signature, args), None,
                             Gio.DBusCallFlags.NONE, 5000, None, done, None)
        self.wait_until(lambda: bool(result))
        if isinstance(result[0], GLib.Error):
            raise result[0]
        return result[0].unpack()

    def enroll(self, finger, value):
        self.enroll_events.clear()
        self.engine.enrolling = value
        self.call("EnrollStart", "(s)", (finger,))
        self.wait_until(lambda: any(done for _, done in self.enroll_events))
        self.assertEqual(self.enroll_events[-1], ("enroll-completed", True))
        self.call("EnrollStop")
        paths = [path for path, data in self.snapshot().items() if print_data(data)[0] == value]
        self.assertEqual(len(paths), 1)
        metadata = print_data(paths[0].read_bytes())[1]
        self.assertEqual(metadata[0], USERNAME)
        self.assertIsNotNone(metadata[3])
        # Serialized identity and storage directory must match the driver.
        self.assertEqual(metadata[4:6], ("goodix_milanl", "0"))
        self.assertEqual(paths[0].relative_to(self.state).parts[:3],
                         (USERNAME, "goodix_milanl", "0"))
        return paths[0]

    def next_request(self):
        self.wait_until(lambda: not self.engine.requests.empty())
        return self.engine.requests.get_nowait()

    def begin_verify(self, finger="right-index-finger"):
        self.verify_events.clear()
        self.call("VerifyStart", "(s)", (finger,))
        return self.next_request()

    def finish_verify(self, expected):
        self.wait_until(lambda: any(done for _, done, _ in self.verify_events))
        self.call("VerifyStop")
        self.assertEqual([(status, done) for status, done, _ in self.verify_events if done],
                         [(expected, True)])
        return self.verify_events[-1][2]

    def test_verify_update_saved_before_signal_and_reloaded(self):
        before = print_data(self.right_path.read_bytes())[1]
        self.assertEqual(self.begin_verify(), (VERIFY, [RIGHT]))
        self.engine.replies.put(match(update=UPDATED))
        saved = self.finish_verify("verify-match")
        self.assertEqual(print_data(saved[self.right_path]), (UPDATED, before))
        self.assertEqual(self.begin_verify(), (VERIFY, [UPDATED]))
        self.engine.replies.put(match())
        self.finish_verify("verify-match")

    def test_identify_only_saves_matched_gallery_print(self):
        left_path = self.enroll("left-index-finger", LEFT)
        original = self.snapshot()
        before = print_data(original[left_path])[1]
        op, gallery = self.begin_verify("any")
        self.assertEqual(op, IDENTIFY)
        self.assertCountEqual(gallery, [RIGHT, LEFT])
        self.engine.replies.put(match(gallery.index(LEFT), UPDATED))
        saved = self.finish_verify("verify-match")
        self.assertEqual(saved[self.right_path], original[self.right_path])
        self.assertEqual(print_data(saved[left_path]), (UPDATED, before))
        self.assertEqual(self.begin_verify("left-index-finger"), (VERIFY, [UPDATED]))
        self.engine.replies.put(match())
        self.finish_verify("verify-match")

    def storage_failure(self, identify):
        if identify:
            self.enroll("left-index-finger", LEFT)
        original = self.snapshot()
        op, gallery = self.begin_verify("any" if identify else "right-index-finger")
        self.assertEqual(op, IDENTIFY if identify else VERIFY)
        index = gallery.index(RIGHT) if identify else 0xffff
        backup = self.right_path.with_name(self.right_path.name + ".backup")
        # Inject only after loading the print. A directory makes saving fail
        # even as root, unlike chmod-based tests, while retaining original data.
        self.right_path.rename(backup)
        self.right_path.mkdir()
        try:
            self.engine.replies.put(match(index, UPDATED))
            self.finish_verify("verify-unknown-error")
            self.assertIn("Error saving matched fingerprint", self.log_path.read_text())
            self.assertEqual(backup.read_bytes(), original[self.right_path])
        finally:
            self.right_path.rmdir()
            backup.rename(self.right_path)
        self.assertEqual(self.snapshot(), original)
        self.assertEqual(self.begin_verify(), (VERIFY, [RIGHT]))
        self.engine.replies.put(match(update=RECOVERED))
        saved = self.finish_verify("verify-match")
        self.assertEqual(print_data(saved[self.right_path]),
                         (RECOVERED, print_data(original[self.right_path])[1]))

    def test_verify_storage_failure_rejects_authentication_and_recovers(self):
        self.storage_failure(False)

    def test_identify_storage_failure_rejects_authentication_and_recovers(self):
        self.storage_failure(True)

    def test_match_without_update(self):
        before = self.snapshot()
        self.assertEqual(self.begin_verify(), (VERIFY, [RIGHT]))
        self.engine.replies.put(match())
        self.assertEqual(self.finish_verify("verify-match"), before)

    def test_retry_no_match_and_cancel_do_not_save(self):
        before = self.snapshot()
        stat = self.right_path.stat()
        self.assertEqual(self.begin_verify(), (VERIFY, [RIGHT]))
        self.engine.replies.put(bytes([RETRY, 1]))
        self.wait_until(lambda: bool(self.verify_events))
        self.assertEqual(self.verify_events, [("verify-retry-scan", False, before)])
        self.assertEqual(self.next_request(), (VERIFY, [RIGHT]))
        self.engine.replies.put(bytes([NO_MATCH]))
        self.assertEqual(self.finish_verify("verify-no-match"), before)
        self.assertEqual(self.begin_verify(), (VERIFY, [RIGHT]))
        self.engine.replies.put(None)
        self.call("VerifyStop")
        self.wait_until(lambda: self.engine.cancelled == 1)
        self.assertNotIn("verify-match", [event[0] for event in self.verify_events])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual((self.right_path.stat().st_ino, self.right_path.stat().st_mtime_ns),
                         (stat.st_ino, stat.st_mtime_ns))
        self.assertEqual(self.begin_verify(), (VERIFY, [RIGHT]))
        self.engine.replies.put(match(update=UPDATED))
        saved = self.finish_verify("verify-match")
        self.assertEqual(print_data(saved[self.right_path])[0], UPDATED)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fprintd", type=Path, required=True)
    library = parser.add_mutually_exclusive_group(required=True)
    library.add_argument("--libfprint-build", type=Path)
    library.add_argument("--libfprint-libdir", type=Path, help="library directory in an unpacked package root")
    args, unittest_args = parser.parse_known_args()
    AdaptedPrintStorageTest.daemon_binary = args.fprintd.resolve()
    AdaptedPrintStorageTest.libfprint_libdir = (args.libfprint_libdir if args.libfprint_libdir else
                                             args.libfprint_build / "libfprint").resolve()
    unittest.main(argv=[__file__] + unittest_args)
