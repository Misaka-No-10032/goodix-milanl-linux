// SPDX-License-Identifier: GPL-2.0-only
#include <linux/acpi.h>
#include <linux/capability.h>
#include <linux/delay.h>
#include <linux/dmi.h>
#include <linux/fs.h>
#include <linux/gpio/consumer.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/unaligned.h>

#include "goodix_milanl_uapi.h"

#define WINDOW_SIZE 0x8000
#define TX_SIZE 0x1000
#define RX_OFFSET 0x1000
#define RX_SIZE (WINDOW_SIZE - RX_OFFSET)

static const guid_t mailbox_guid =
	GUID_INIT(0xcc58b68a, 0x4479, 0x4893, 0xa8, 0xbb, 0x96, 0x12, 0x09, 0xdb, 0x59, 0xe5);

static bool enable_raw_tx;
module_param(enable_raw_tx, bool, 0400);
MODULE_PARM_DESC(enable_raw_tx, "Allow raw sensor commands required by the fingerprint engine");

static bool enable_sealed_input;
module_param(enable_sealed_input, bool, 0400);
MODULE_PARM_DESC(enable_sealed_input, "Allow the fingerprint engine to read sealed firmware enclave input");

/* OEM chip-ID read command for the MilanL sensor. */
static const u8 read_id_request[] = {
	0xa0, 0x09, 0x00, 0xa9, 0x82, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x04, 0x00, 0x1e,
};
static const u8 mcu_state_request[] = {
	0xa0, 0x05, 0x00, 0xa5, 0xae, 0x02, 0x00, 0x55, 0xa5,
};
static const u8 pmk_hash_request[] = {
	0xa0, 0x04, 0x00, 0xa4, 0xe4, 0x01, 0x00, 0xc5,
};
static const u8 otp_request[] = {
	0xa0, 0x06, 0x00, 0xa6, 0xa6, 0x03, 0x00, 0x00, 0x00, 0x01,
};
static const u8 image_request[] = {
	0xa0, 0x06, 0x00, 0xa6, 0x20, 0x03, 0x00, 0x01, 0x00, 0x86,
};
static const u8 nav_request[] = {
	0xa0, 0x06, 0x00, 0xa6, 0x50, 0x03, 0x00, 0x01, 0x00, 0x56,
};
static const u8 idle_request[] = {
	0xa0, 0x06, 0x00, 0xa6, 0x70, 0x03, 0x00, 0x14, 0x00, 0x23,
};

struct goodix_milanl_packet {
	struct list_head node;
	size_t len;
	u8 data[];
};

struct goodix_milanl {
	struct miscdevice misc;
	void __iomem *window;
	acpi_handle handle;
	struct gpio_desc *driver_out;
	int irq;
	struct mutex tx_lock;
	struct mutex rx_lock;
	wait_queue_head_t rx_wait;
	struct list_head rx_queue;
	unsigned int rx_count;
	int rx_error;
	atomic_t opened;
};

struct goodix_milanl_file {
	struct goodix_milanl *fp;
	struct goodix_milanl_packet *packet;
};

static irqreturn_t goodix_milanl_irq(int irq, void *data)
{
	struct goodix_milanl *fp = data;
	u8 header[4];
	struct goodix_milanl_packet *packet;
	size_t len;

	memcpy_fromio(header, fp->window + RX_OFFSET, sizeof(header));
	len = (size_t)header[1] | (size_t)header[2] << 8;
	if ((header[0] >> 4 != 0xa && header[0] >> 4 != 0xb) ||
	    header[3] != (u8)(header[0] + header[1] + header[2]) ||
	    len + 4 > RX_SIZE)
		return IRQ_HANDLED;

	packet = kmalloc(struct_size(packet, data, len + 4), GFP_KERNEL);
	if (packet)
		memcpy_fromio(packet->data, fp->window + RX_OFFSET, len + 4);
	/* ACPI uses level-low IRQs. OEM WriteDriverOutGPIO (0x180018744)
	 * holds the acknowledgement low for at least 5 ms before raising it.
	 * Finish that handshake before publishing the copied mailbox to readers.
	 */
	gpiod_set_value_cansleep(fp->driver_out, 0);
	usleep_range(5000, 6000);
	gpiod_set_value_cansleep(fp->driver_out, 1);
	mutex_lock(&fp->rx_lock);
	if (!packet) {
		fp->rx_error = -ENOMEM;
	} else if (fp->rx_count >= 32) {
		fp->rx_error = -ENOBUFS;
		kfree_sensitive(packet);
	} else {
		packet->len = len + 4;
		list_add_tail(&packet->node, &fp->rx_queue);
		fp->rx_count++;
	}
	mutex_unlock(&fp->rx_lock);
	wake_up_interruptible(&fp->rx_wait);
	return IRQ_HANDLED;
}

static void goodix_milanl_purge_rx(struct goodix_milanl *fp)
{
	struct goodix_milanl_packet *packet, *next;

	mutex_lock(&fp->rx_lock);
	list_for_each_entry_safe(packet, next, &fp->rx_queue, node) {
		list_del(&packet->node);
		kfree_sensitive(packet);
	}
	fp->rx_count = 0;
	fp->rx_error = 0;
	mutex_unlock(&fp->rx_lock);
}

static int goodix_milanl_open(struct inode *inode, struct file *file)
{
	struct goodix_milanl *fp = container_of(file->private_data, struct goodix_milanl, misc);
	struct goodix_milanl_file *ctx;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;
	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;
	if (atomic_cmpxchg(&fp->opened, 0, 1)) {
		kfree(ctx);
		return -EBUSY;
	}
	ctx->fp = fp;
	goodix_milanl_purge_rx(fp);
	file->private_data = ctx;
	return 0;
}

static int goodix_milanl_release(struct inode *inode, struct file *file)
{
	struct goodix_milanl_file *ctx = file->private_data;

	kfree_sensitive(ctx->packet);
	goodix_milanl_purge_rx(ctx->fp);
	atomic_set(&ctx->fp->opened, 0);
	kfree(ctx);
	return 0;
}

static ssize_t goodix_milanl_read(struct file *file, char __user *buf, size_t count,
			     loff_t *pos)
{
	struct goodix_milanl_file *ctx = file->private_data;
	struct goodix_milanl *fp = ctx->fp;
	size_t len;

	if (!count)
		return 0;
	mutex_lock(&fp->rx_lock);
	if (fp->rx_error) {
		int error = fp->rx_error;

		fp->rx_error = 0;
		mutex_unlock(&fp->rx_lock);
		return error;
	}
	if (*pos == 0 && !list_empty(&fp->rx_queue)) {
		kfree_sensitive(ctx->packet);
		ctx->packet = list_first_entry(&fp->rx_queue, struct goodix_milanl_packet, node);
		list_del(&ctx->packet->node);
		fp->rx_count--;
	}
	if (!ctx->packet || *pos < 0 || *pos >= ctx->packet->len) {
		mutex_unlock(&fp->rx_lock);
		return 0;
	}
	len = min(count, ctx->packet->len - (size_t)*pos);
	if (copy_to_user(buf, ctx->packet->data + *pos, len)) {
		mutex_unlock(&fp->rx_lock);
		return -EFAULT;
	}
	*pos += len;
	mutex_unlock(&fp->rx_lock);
	return len;
}

static ssize_t goodix_milanl_write(struct file *file, const char __user *buf, size_t count,
			      loff_t *pos)
{
	struct goodix_milanl_file *ctx = file->private_data;
	struct goodix_milanl *fp = ctx->fp;
	union acpi_object *reply;
	u8 *tx;

	if (count < 4 || count > TX_SIZE)
		return -EMSGSIZE;
	tx = kzalloc(round_up(count, 8), GFP_KERNEL);
	if (!tx)
		return -ENOMEM;
	if (copy_from_user(tx, buf, count)) {
		kfree(tx);
		return -EFAULT;
	}
	if ((tx[0] >> 4 != 0xa && tx[0] >> 4 != 0xb) ||
	    tx[3] != (u8)(tx[0] + tx[1] + tx[2]) ||
	    (size_t)(tx[1] | tx[2] << 8) + 4 != count) {
		kfree(tx);
		return -EINVAL;
	}
	if (!enable_raw_tx &&
	    !((count == sizeof(read_id_request) &&
	       !memcmp(tx, read_id_request, sizeof(read_id_request))) ||
	      (count == sizeof(mcu_state_request) &&
	       !memcmp(tx, mcu_state_request, sizeof(mcu_state_request))) ||
	      (count == sizeof(pmk_hash_request) &&
	       !memcmp(tx, pmk_hash_request, sizeof(pmk_hash_request))) ||
	      (count == sizeof(otp_request) &&
	       !memcmp(tx, otp_request, sizeof(otp_request))) ||
	      (count == sizeof(image_request) &&
	       !memcmp(tx, image_request, sizeof(image_request))) ||
	      (count == sizeof(nav_request) &&
	       !memcmp(tx, nav_request, sizeof(nav_request))) ||
	      (count == sizeof(idle_request) &&
	       !memcmp(tx, idle_request, sizeof(idle_request))))) {
		kfree(tx);
		return -EPERM;
	}

	mutex_lock(&fp->tx_lock);
	memcpy_toio(fp->window, tx, round_up(count, 8));
	wmb();
	/* _DSM function 2 rings the EC doorbell; it does not confirm a reply. */
	reply = acpi_evaluate_dsm(fp->handle, &mailbox_guid, 0, 2, NULL);
	mutex_unlock(&fp->tx_lock);
	kfree(tx);
	if (!reply)
		return -EIO;
	ACPI_FREE(reply);
	return count;
}

static long goodix_milanl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct goodix_milanl *fp = ((struct goodix_milanl_file *)file->private_data)->fp;
	struct goodix_milanl_sealed_input *input = NULL;
	union acpi_object *reply;
	const u8 *data;
	u32 blob_bytes, plaintext_offset, payload_bytes;
	int ret = 0;

	if (cmd != GOODIX_MILANL_IOC_SEALED_INPUT)
		return -ENOTTY;
	if (!capable(CAP_SYS_RAWIO) || !enable_sealed_input)
		return -EPERM;
	reply = acpi_evaluate_dsm(fp->handle, &mailbox_guid, 0, 1, NULL);
	if (!reply)
		return -EIO;
	if (reply->type != ACPI_TYPE_BUFFER || reply->buffer.length < 4) {
		ret = -EPROTO;
		goto out;
	}
	data = reply->buffer.pointer;
	blob_bytes = get_unaligned_be16(data + 2);
	if (blob_bytes > reply->buffer.length - 4 || blob_bytes < 0x230) {
		ret = -EPROTO;
		goto out;
	}
	data += 4;
	plaintext_offset = get_unaligned_le32(data + 0x200);
	payload_bytes = get_unaligned_le32(data + 0x210);
	if (blob_bytes > sizeof(input->sealed_data) ||
	    payload_bytes != blob_bytes - 0x230 ||
	    plaintext_offset > payload_bytes ||
	    get_unaligned_le16(data) != 4 || get_unaligned_le16(data + 2) != 2) {
		ret = -EPROTO;
		goto out;
	}
	input = kzalloc(sizeof(*input), GFP_KERNEL);
	if (!input) {
		ret = -ENOMEM;
		goto out;
	}
	input->blob_bytes = blob_bytes;
	memcpy(input->sealed_data, data, blob_bytes);
	if (copy_to_user((void __user *)arg, input, sizeof(*input)))
		ret = -EFAULT;
out:
	kfree_sensitive(input);
	if (reply->type == ACPI_TYPE_BUFFER)
		memzero_explicit(reply->buffer.pointer, reply->buffer.length);
	ACPI_FREE(reply);
	return ret;
}

static __poll_t goodix_milanl_poll(struct file *file, poll_table *wait)
{
	struct goodix_milanl_file *ctx = file->private_data;
	struct goodix_milanl *fp = ctx->fp;

	poll_wait(file, &fp->rx_wait, wait);
	if (READ_ONCE(fp->rx_error))
		return EPOLLERR;
	return READ_ONCE(fp->rx_count) ? EPOLLIN | EPOLLRDNORM : 0;
}

static loff_t goodix_milanl_llseek(struct file *file, loff_t offset, int whence)
{
	return fixed_size_llseek(file, offset, whence, RX_SIZE);
}

static const struct file_operations goodix_milanl_fops = {
	.owner = THIS_MODULE,
	.open = goodix_milanl_open,
	.release = goodix_milanl_release,
	.read = goodix_milanl_read,
	.write = goodix_milanl_write,
	.poll = goodix_milanl_poll,
	.unlocked_ioctl = goodix_milanl_ioctl,
	.llseek = goodix_milanl_llseek,
};

static int goodix_milanl_probe(struct platform_device *pdev)
{
	struct resource *res;
	struct goodix_milanl *fp;
	int ret;

	if (!dmi_match(DMI_PRODUCT_NAME, "MACHR-WX9"))
		return -ENODEV;
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res || resource_size(res) < WINDOW_SIZE)
		return -ENODEV;
	fp = devm_kzalloc(&pdev->dev, sizeof(*fp), GFP_KERNEL);
	if (!fp)
		return -ENOMEM;
	fp->window = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(fp->window))
		return PTR_ERR(fp->window);
	fp->handle = ACPI_HANDLE(&pdev->dev);
	if (!fp->handle)
		return -ENODEV;
	fp->driver_out = devm_gpiod_get_index(&pdev->dev, NULL, 1, GPIOD_OUT_HIGH);
	if (IS_ERR(fp->driver_out))
		return dev_err_probe(&pdev->dev, PTR_ERR(fp->driver_out), "GPIO output unavailable\n");
	fp->irq = acpi_dev_gpio_irq_get(ACPI_COMPANION(&pdev->dev), 0);
	if (fp->irq < 0)
		return dev_err_probe(&pdev->dev, fp->irq, "GPIO interrupt unavailable\n");
	mutex_init(&fp->tx_lock);
	mutex_init(&fp->rx_lock);
	init_waitqueue_head(&fp->rx_wait);
	INIT_LIST_HEAD(&fp->rx_queue);
	ret = devm_request_threaded_irq(&pdev->dev, fp->irq, NULL, goodix_milanl_irq,
					IRQF_ONESHOT, "goodix_milanl_transport", fp);
	if (ret)
		return dev_err_probe(&pdev->dev, ret, "IRQ request failed\n");
	atomic_set(&fp->opened, 0);
	fp->misc.minor = MISC_DYNAMIC_MINOR;
	fp->misc.name = "goodix-milanl-raw";
	fp->misc.mode = 0600;
	fp->misc.fops = &goodix_milanl_fops;
	fp->misc.parent = &pdev->dev;
	ret = misc_register(&fp->misc);
	if (ret)
		return ret;
	platform_set_drvdata(pdev, fp);
	return 0;
}

static void goodix_milanl_remove(struct platform_device *pdev)
{
	struct goodix_milanl *fp = platform_get_drvdata(pdev);

	misc_deregister(&fp->misc);
	devm_free_irq(&pdev->dev, fp->irq, fp);
	goodix_milanl_purge_rx(fp);
}

static const struct acpi_device_id goodix_milanl_acpi_ids[] = {
	{ "GXFP51B7", 0 },
	{ }
};
MODULE_DEVICE_TABLE(acpi, goodix_milanl_acpi_ids);

static struct platform_driver goodix_milanl_driver = {
	.probe = goodix_milanl_probe,
	.remove = goodix_milanl_remove,
	.driver = {
		.name = "goodix_milanl_transport",
		.acpi_match_table = goodix_milanl_acpi_ids,
	},
};
module_platform_driver(goodix_milanl_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Goodix MilanL GXFP51B7 raw ACPI/EC mailbox transport");
