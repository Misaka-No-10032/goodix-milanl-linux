"""Compile the actual IRQ handler with public RAM/GPIO mocks; never load a module."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which('cc'), 'C compiler required')
class TransportIRQTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix='goodix-milanl-irq-test-')
        cls.addClassCleanup(directory.cleanup)
        root = Path(directory.name)
        source = (Path(__file__).parents[2] / 'kernel/goodix_milanl_transport.c').read_text()
        handler = source[source.index('static irqreturn_t goodix_milanl_irq('):
                         source.index('static void goodix_milanl_purge_rx(')]
        mock = r'''
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef uint8_t u8;
typedef int irqreturn_t;
#define IRQ_HANDLED 1
#define GFP_KERNEL 0
#define RX_OFFSET 0x1000
#define RX_SIZE 0x7000
#define struct_size(p, member, count) (sizeof(*(p)) + (count))
struct list_head { int unused; };
struct goodix_milanl_packet { struct list_head node; size_t len; u8 data[]; };
struct goodix_milanl {
    u8 *window;
    void *driver_out;
    int rx_lock, rx_wait;
    struct list_head rx_queue;
    unsigned rx_count;
    int rx_error;
};
static struct goodix_milanl *current;
static struct goodix_milanl_packet *packets[2];
static unsigned copies, enqueued, low_us, high_us, initial_count, early_publish;
static int allocation_failure, acknowledge_done, locked;
static char events[128];
static u8 window[0x8000];
static const u8 expected[] = {0xa0,6,0,0xa6,0xb0,3,0,0x82,1,0x74};
static void event(char c) { size_t n = strlen(events); events[n] = c; events[n+1] = 0; }
static void memcpy_fromio(void *to, const void *from, size_t bytes)
{
    event(bytes == 4 ? 'h' : 'c');
    memcpy(to, from, bytes);
    copies++;
}
static void *kmalloc(size_t bytes, int flags)
{
    event('a');
    return allocation_failure ? NULL : malloc(bytes);
}
static void mutex_lock(int *mutex) { event('l'); locked = 1; }
static void mutex_unlock(int *mutex) { event('u'); locked = 0; }
static void kfree_sensitive(void *p) { event('f'); free(p); }
static void gpiod_set_value_cansleep(void *gpio, int value)
{
    event(value ? '1' : '0');
    if (current->rx_count != initial_count || locked) early_publish++;
    if (!value) {
        acknowledge_done = 0;
        /* Model the MCU reusing shared RAM once ACK starts. */
        memset(window + RX_OFFSET, 0xee, sizeof(expected));
    } else acknowledge_done = low_us >= 5000 && high_us >= low_us;
}
static void usleep_range(unsigned low, unsigned high)
{
    event('s');
    low_us = low; high_us = high;
}
static void list_add_tail(struct list_head *node, struct list_head *head)
{
    event('q');
    if (!acknowledge_done || !locked || enqueued >= 2) abort();
    packets[enqueued++] = (void *)((char *)node - offsetof(struct goodix_milanl_packet, node));
}
static void wake_up_interruptible(int *wait)
{
    event('w');
    if (!acknowledge_done || locked) abort();
}
'''
        main = r'''
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    int mode = atoi(argv[1]);
    struct goodix_milanl fp = {.window = window};
    current = &fp;
    allocation_failure = mode == 1;
    if (mode == 2) fp.rx_count = 32;
    initial_count = fp.rx_count;
    memcpy(window + RX_OFFSET, expected, sizeof(expected));
    if (mode == 3) window[RX_OFFSET + 3] ^= 1;
    if (mode == 4) {
        window[RX_OFFSET + 1] = 0xff; window[RX_OFFSET + 2] = 0x7f;
        window[RX_OFFSET + 3] = (u8)(0xa0 + 0xff + 0x7f);
    }
    if (goodix_milanl_irq(0, &fp) != IRQ_HANDLED) return 3;
    if (mode == 5) {
        /* Identical bytes can be distinct legitimate arrivals: never deduplicate. */
        memcpy(window + RX_OFFSET, expected, sizeof(expected));
        initial_count = fp.rx_count;
        if (goodix_milanl_irq(0, &fp) != IRQ_HANDLED) return 3;
    }
    int copied = 1;
    for (unsigned i = 0; i < enqueued; i++) {
        copied &= packets[i]->len == sizeof(expected) && !memcmp(packets[i]->data, expected, sizeof(expected));
        free(packets[i]);
    }
    printf("{\"events\":\"%s\",\"low_us\":%u,\"high_us\":%u,\"count\":%u,"
           "\"enqueued\":%u,\"error\":%d,\"early_publish\":%u,\"copied\":%d}\n",
           events, low_us, high_us, fp.rx_count, enqueued, fp.rx_error, early_publish, copied);
    return 0;
}
'''
        (root / 'test.c').write_text(mock + handler + main)
        cls.binary = root / 'test'
        subprocess.run(['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                        str(root / 'test.c'), '-o', str(cls.binary)], check=True, capture_output=True, text=True)

    def exercise(self, mode):
        result = subprocess.run([str(self.binary), str(mode)], check=True, capture_output=True, text=True, timeout=5)
        return json.loads(result.stdout)

    def test_copy_before_ack_and_minimum_low_time_before_publishing(self):
        result = self.exercise(0)
        self.assertEqual(result['events'], 'hac0s1lquw')
        self.assertEqual(result['low_us'], 5000)
        self.assertGreaterEqual(result['high_us'], result['low_us'])
        self.assertEqual(result['early_publish'], 0)
        self.assertEqual(result['copied'], 1)
        self.assertEqual(result['enqueued'], 1)
        self.assertEqual(result['error'], 0)

    def test_allocation_failure_still_acknowledges_and_reports_error(self):
        result = self.exercise(1)
        self.assertEqual(result['events'], 'ha0s1luw')
        self.assertEqual(result['enqueued'], 0)
        self.assertEqual(result['error'], -12)  # ENOMEM

    def test_queue_full_still_acknowledges_and_preserves_explicit_loss_error(self):
        result = self.exercise(2)
        self.assertEqual(result['events'], 'hac0s1lfuw')
        self.assertEqual(result['enqueued'], 0)
        self.assertEqual(result['count'], 32)
        self.assertEqual(result['error'], -105)  # ENOBUFS

    def test_invalid_header_or_oversized_payload_is_not_copied_or_acknowledged(self):
        for mode in (3, 4):
            with self.subTest(mode=mode):
                result = self.exercise(mode)
                self.assertEqual(result['events'], 'h')
                self.assertEqual(result['enqueued'], 0)
                self.assertEqual(result['low_us'], 0)

    def test_identical_packets_are_not_silently_deduplicated(self):
        result = self.exercise(5)
        self.assertEqual(result['events'], 'hac0s1lquw' * 2)
        self.assertEqual(result['count'], 2)
        self.assertEqual(result['copied'], 1)
        self.assertEqual(result['early_publish'], 0)


if __name__ == '__main__':
    unittest.main()
