#!/usr/bin/env python3
"""Check a fakeroot tool's SysV receive handling; no root or hardware access."""
import argparse
import errno
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


FIXTURE = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <unistd.h>

#ifdef IPC_PRELOAD
static int fault, remaining;

void inject_receive_error(int error)
{
    fault = error;
    remaining = error == EINTR ? 3 : (error != 0);
}

int pending_receive_errors(void)
{
    return remaining;
}

ssize_t msgrcv(int queue, void *message, size_t size, long type, int flags)
{
    static ssize_t (*receive)(int, void *, size_t, long, int);
    if (!receive)
        receive = dlsym(RTLD_NEXT, "msgrcv");
    if (remaining) {
        --remaining;
        errno = fault;
        return -1;
    }
    return receive(queue, message, size, type, flags);
}
#else
int main(int argc, char **argv)
{
    struct stat metadata;
    void (*inject)(int) = dlsym(RTLD_DEFAULT, "inject_receive_error");
    int (*pending)(void) = dlsym(RTLD_DEFAULT, "pending_receive_errors");
    if (argc != 3 || !inject || !pending)
        return 2;
    if (chown(argv[2], 12345, 23456) || chmod(argv[2], 0640) ||
        stat(argv[2], &metadata))
        return 3;
    if (metadata.st_uid != 12345 || metadata.st_gid != 23456)
        return 4;

    inject(atoi(argv[1]));
    if (stat(argv[2], &metadata) || pending())
        return 5;
    /* Change the reply so a stale response cannot pass the next check. */
    if (chown(argv[2], 34567, 45678) || stat(argv[2], &metadata))
        return 6;
    printf("%u:%u:%o\n", metadata.st_uid, metadata.st_gid, metadata.st_mode & 07777);
    return 0;
}
#endif
'''


class FakerootIPCTests(unittest.TestCase):
    fakeroot = 'fakeroot'

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='fakeroot-ipc-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.work = Path(cls.temporary.name)
        source = cls.work / 'fixture.c'
        source.write_text(FIXTURE)
        cls.library = cls.work / 'receive.so'
        cls.client = cls.work / 'client'
        for output, flags in ((cls.library, ['-shared', '-fPIC', '-DIPC_PRELOAD']),
                              (cls.client, [])):
            subprocess.run(['cc', '-Wall', '-Wextra', '-Werror', '-O2', *flags,
                            str(source), '-ldl', '-o', str(output)], check=True)

    def run_case(self, error):
        path = self.work / self._testMethodName
        path.touch(mode=0o600)
        env = dict(os.environ, LC_ALL='C', LD_PRELOAD=str(self.library))
        result = subprocess.run([self.fakeroot, '--', str(self.client), str(error), str(path)],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '34567:45678:640\n')
        # The changed owner exists only in faked's database, not on the host.
        self.assertEqual(path.stat().st_uid, os.getuid())
        return result

    def test_normal_receive_preserves_fake_metadata(self):
        self.assertEqual(self.run_case(0).stderr, '')

    def test_interrupted_receive_retries_before_decoding(self):
        self.assertEqual(self.run_case(errno.EINTR).stderr, '')

    def test_noninterrupt_receive_error_is_reported(self):
        self.assertEqual(self.run_case(errno.EIO).stderr,
                         'fakeroot internal error #5: Input/output error\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fakeroot', default='fakeroot', help='fakeroot launcher to test')
    args, unittest_args = parser.parse_known_args()
    FakerootIPCTests.fakeroot = args.fakeroot
    unittest.main(argv=[__file__] + unittest_args)
