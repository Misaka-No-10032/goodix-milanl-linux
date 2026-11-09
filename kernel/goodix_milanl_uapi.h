/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GOODIX_MILANL_UAPI_H
#define GOODIX_MILANL_UAPI_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct goodix_milanl_sealed_input {
	__u32 blob_bytes;
	__u8 sealed_data[2048];
};

#define GOODIX_MILANL_IOC_SEALED_INPUT \
	_IOR('M', 0x02, struct goodix_milanl_sealed_input)

#endif
