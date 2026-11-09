/* SPDX-License-Identifier: GPL-2.0-only */
/* Goodix MilanL engine <-> libfprint driver wire protocol.
 *
 * The libfprint driver is the CLIENT; the root engine daemon is the SERVER
 * listening on an AF_UNIX stream socket. Each request receives one response.
 * The only permitted in-flight control frame is SUSPEND (length=1, opcode=7),
 * sent after the complete original request. The original response is either
 * its normal result or R_INTERRUPTED, followed by SUSPEND's own response.
 * Disconnect is implicit CANCEL, including during capture. The engine finishes
 * that connection's teardown before serving another client. RESUME stays on
 * the same connection: SUSPEND retains OEM host enrollment metadata, not the
 * enclave's samples, and RESUME must not recreate enrollment via Engine10.
 * Other requests require no outstanding request. The driver reports progress
 * and retries; the engine owns the sensor, enclaves and SGX-sealed templates.
 *
 * Framing: every message is  u32le length  followed by  <length> bytes.
 * The framed body starts with one u8 opcode/result, then opcode-specific
 * fields in the order documented below. Multi-byte integers are little-endian.
 * A "blob" field is  u32le size  followed by <size> raw bytes (the opaque
 * SGX-sealed template; this protocol never carries fingerprint pixels).
 *
 * The Rust engine uses userspace/engine/src/protocol.rs.
 * Bump GOODIX_MILANL_PROTO_VERSION on any wire-visible change and reject a
 * mismatch in the HELLO exchange.
 *
 * OEM enclave mapping in userspace/engine/src/sgx/templates.rs:
 *   ENROLL_BEGIN         Engine ordinal 10 creates a 12-sample enrollment.
 *   ENROLL_CAPTURE       FDT-down + one accepted frame + merge (ord 11/12).
 *                        R_ENROLL_STAGE carries the accepted count; frame 12
 *                        seals the template (ord 14/15) as R_ENROLL_DONE.
 *   VERIFY / IDENTIFY    One captured frame is compared with each caller blob
 *                        (ord 17); adaptation (ord 16) fills the optional
 *                        updated blob in R_MATCH.
 * The blob is SGX-sealed (at least 560 B, capped at GOODIX_MILANL_MAX_BLOB).
 * The engine keeps no persistent copy: fprintd owns the only store.
 */
#ifndef GOODIX_MILANL_PROTO_H
#define GOODIX_MILANL_PROTO_H

#include <stdint.h>

#define GOODIX_MILANL_PROTO_VERSION 2u

/* Independent ceilings for opaque blobs, gallery count and complete frame bodies.
 * Reject malformed lengths before allocating; adapted template sizes can grow. */
#define GOODIX_MILANL_MAX_BLOB    (1024u * 1024u)
#define GOODIX_MILANL_MAX_GALLERY 16u
#define GOODIX_MILANL_MAX_MESSAGE (GOODIX_MILANL_MAX_GALLERY * (GOODIX_MILANL_MAX_BLOB + 4u) + 3u)

/* Requests: driver -> engine. */
enum goodix_milanl_op {
    GOODIX_MILANL_OP_HELLO = 1,     /* u32 proto_version                                   */
    GOODIX_MILANL_OP_ENROLL_BEGIN,  /* (no fields)                                          */
    GOODIX_MILANL_OP_ENROLL_CAPTURE,/* (no fields) one touch -> one enroll stage            */
    GOODIX_MILANL_OP_VERIFY,        /* blob                                                 */
    GOODIX_MILANL_OP_IDENTIFY,      /* u16 count, then count * blob                         */
    GOODIX_MILANL_OP_CANCEL,        /* (no fields) discard session; in-flight uses EOF      */
    GOODIX_MILANL_OP_SUSPEND,       /* (no fields) tear enclaves/sensor down before sleep   */
    GOODIX_MILANL_OP_RESUME,        /* (no fields) rebuild after resume                     */
};

/* Responses: engine -> driver. */
enum goodix_milanl_result {
    GOODIX_MILANL_R_OK = 1,         /* generic success, no payload                          */
    GOODIX_MILANL_R_HELLO,          /* u32 proto_version, u16 enroll_stages, u32 features   */
    GOODIX_MILANL_R_ENROLL_STAGE,   /* u16 stages_done  (finger captured, not yet complete) */
    GOODIX_MILANL_R_ENROLL_DONE,    /* blob  (final sealed template)                        */
    GOODIX_MILANL_R_MATCH,          /* u16 index (0xffff for verify), then opt. updated blob:
                                *   u8 has_update; if 1, blob (adapted template)       */
    GOODIX_MILANL_R_NO_MATCH,       /* (no fields)                                          */
    GOODIX_MILANL_R_RETRY,          /* u8 reason (enum goodix_milanl_retry): bad frame, re-press */
    GOODIX_MILANL_R_ERROR,          /* u8 reason (enum goodix_milanl_err)                        */
    GOODIX_MILANL_R_INTERRUPTED,    /* no payload; original request interrupted by SUSPEND   */
};

/* Advisory to the user between captures; maps onto FpDeviceRetry. */
enum goodix_milanl_retry {
    GOODIX_MILANL_RETRY_GENERAL = 1,/* unusable frame, press again                          */
    GOODIX_MILANL_RETRY_SHORT,      /* lifted too soon / partial                            */
    GOODIX_MILANL_RETRY_CENTER,     /* off-centre, recentre the finger                      */
};

/* Terminal failures; maps onto FpDeviceError. */
enum goodix_milanl_err {
    GOODIX_MILANL_ERR_GENERAL = 1,  /* unspecified engine failure                           */
    GOODIX_MILANL_ERR_PROTO,        /* malformed/unsupported request                        */
    GOODIX_MILANL_ERR_BUSY,         /* another op is in flight                              */
    GOODIX_MILANL_ERR_NO_SENSOR,    /* sensor/enclave not available (e.g. after suspend)    */
    GOODIX_MILANL_ERR_DATA,         /* template blob rejected (corrupt / wrong CPU)         */
};

/* HELLO feature bits the engine advertises. */
#define GOODIX_MILANL_FEAT_IDENTIFY      (1u << 0)
#define GOODIX_MILANL_FEAT_ADAPT         (1u << 1) /* verify/identify may return an update  */

#endif /* GOODIX_MILANL_PROTO_H */
