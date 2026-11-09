/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * libfprint driver for the Goodix MilanL sensor (ACPI GXFP51B7).
 * Capture and matching are provided by the Goodix MilanL engine daemon.
 *
 * The engine owns the sensor and SGX enclaves. This virtual device connects
 * to the AF_UNIX socket named by GOODIX_MILANL_ENGINE. Templates are host-stored:
 * fprintd persists the opaque sealed blobs; no fingerprint images cross the
 * socket. Protocol v2 permits SUSPEND to interrupt one outstanding request.
 */

#define FP_COMPONENT "goodix_milanl"

#include <gio/gunixsocketaddress.h>

#include "drivers_api.h"
#include "goodix_milanl_proto.h"

#define DEFAULT_ENROLL_STAGES 12

typedef enum
{
  SESSION_START,
  SESSION_CONNECT,
  SESSION_WRITE,
  SESSION_READ_HEADER,
  SESSION_READ_BODY,
  SESSION_RESPONSE,
  SESSION_NUM_STATES,
} SessionState;

typedef struct
{
  GCancellable *cancellable;
  GByteArray   *request;
  GError       *io_error;
  guint         pending_io;
  guint8        resume_opcode;
  gboolean      request_written;
  gboolean      suspend_sent;
  gboolean      terminal;
  gboolean      resumed_stage;
  guint8        header[4];
  guint8       *response;
  gsize         response_len;
  guint8        opcode;
  guint16       completed;
  guint8        result;
  guint8        retry;
  FpPrint      *match; /* Borrowed from the active libfprint action. */
  GBytes       *blob;
} Session;

struct _FpiDeviceGoodixMilanl
{
  FpDevice           parent;
  GSocketConnection *conn;
  FpiSsm            *ssm;
  guint16            enroll_stages;
  guint32            features;
  gboolean           suspend_requested;
  gboolean           paused;
  gboolean           resuming;
};
G_DECLARE_FINAL_TYPE (FpiDeviceGoodixMilanl, fpi_device_goodix_milanl, FPI, DEVICE_GOODIX_MILANL, FpDevice)
G_DEFINE_TYPE (FpiDeviceGoodixMilanl, fpi_device_goodix_milanl, FP_TYPE_DEVICE)

static void start_session (FpDevice *device);
static void send_suspend (FpiSsm *ssm);

/* Request encoding and bounds-checked response decoding. */

static void
put_u8 (GByteArray *b, guint8 v)
{
  g_byte_array_append (b, &v, 1);
}

static void
put_u16 (GByteArray *b, guint16 v)
{
  guint8 p[2] = { v & 0xff, (v >> 8) & 0xff };

  g_byte_array_append (b, p, 2);
}

static void
put_u32 (GByteArray *b, guint32 v)
{
  guint8 p[4] = { v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff };

  g_byte_array_append (b, p, 4);
}

static void
put_blob (GByteArray *b, GBytes *blob)
{
  gsize len;
  const guint8 *data = g_bytes_get_data (blob, &len);

  put_u32 (b, len);
  g_byte_array_append (b, data, len);
}

typedef struct
{
  const guint8 *p;
  gsize         len;
  gsize         off;
  gboolean      ok;
} Cursor;

static guint8
get_u8 (Cursor *c)
{
  if (!c->ok || c->off + 1 > c->len)
    return (c->ok = FALSE), 0;
  return c->p[c->off++];
}

static guint16
get_u16 (Cursor *c)
{
  guint16 v;

  if (!c->ok || c->off + 2 > c->len)
    return (c->ok = FALSE), 0;
  v = c->p[c->off] | ((guint16) c->p[c->off + 1] << 8);
  c->off += 2;
  return v;
}

static guint32
get_u32 (Cursor *c)
{
  guint32 v;

  if (!c->ok || c->off + 4 > c->len)
    return (c->ok = FALSE), 0;
  v = c->p[c->off] | ((guint32) c->p[c->off + 1] << 8) |
      ((guint32) c->p[c->off + 2] << 16) | ((guint32) c->p[c->off + 3] << 24);
  c->off += 4;
  return v;
}

static GBytes *
get_blob (Cursor *c)
{
  guint32 n = get_u32 (c);
  GBytes *blob;

  if (!c->ok || n == 0 || n > GOODIX_MILANL_MAX_BLOB || n > c->len - c->off)
    return (c->ok = FALSE), NULL;
  blob = g_bytes_new (c->p + c->off, n);
  c->off += n;
  return blob;
}

static gboolean
cursor_done (Cursor *c)
{
  return c->ok && c->off == c->len;
}

/* Mapping engine failures onto libfprint errors. */

static GError *
retry_error (guint8 reason)
{
  switch (reason)
    {
    case GOODIX_MILANL_RETRY_SHORT:
      return fpi_device_retry_new (FP_DEVICE_RETRY_TOO_SHORT);

    case GOODIX_MILANL_RETRY_CENTER:
      return fpi_device_retry_new (FP_DEVICE_RETRY_CENTER_FINGER);

    default:
      return fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL);
    }
}

static GError *
engine_error (guint8 reason)
{
  switch (reason)
    {
    case GOODIX_MILANL_ERR_PROTO:
    case GOODIX_MILANL_ERR_DATA:
      return fpi_device_error_new (FP_DEVICE_ERROR_DATA_INVALID);

    case GOODIX_MILANL_ERR_BUSY:
      return fpi_device_error_new (FP_DEVICE_ERROR_BUSY);

    case GOODIX_MILANL_ERR_NO_SENSOR:
      return fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED);

    default:
      return fpi_device_error_new (FP_DEVICE_ERROR_GENERAL);
    }
}

static GError *
cancelled_error (void)
{
  return g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation cancelled");
}

/* FpPrint <-> sealed blob. Only enrollment initializes the print type. */

static void
set_print_blob (FpPrint *print, GBytes *blob)
{
  gsize len;
  gconstpointer data = g_bytes_get_data (blob, &len);
  GVariant *v = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, data, len, 1);

  g_object_set (print, "fpi-data", v, NULL);
}

static GBytes *
blob_from_print (FpDevice *device, FpPrint *print)
{
  g_autoptr(GVariant) v = NULL;
  gsize len;
  gconstpointer data;

  if (!fp_print_compatible (print, device) || fpi_print_get_type (print) != FPI_PRINT_RAW)
    return NULL;
  g_object_get (print, "fpi-data", &v, NULL);
  if (!v || !g_variant_is_of_type (v, G_VARIANT_TYPE ("ay")))
    return NULL;
  data = g_variant_get_fixed_array (v, &len, 1);
  if (len == 0 || len > GOODIX_MILANL_MAX_BLOB)
    return NULL;
  return g_bytes_new (data, len);
}

/* Closing the socket is implicit CANCEL, never SUSPEND. Unlike closing a GIO
 * stream, this also works while its async read/write is still pending. The
 * engine tears down this session before servicing the next connection. */
static void
disconnect_engine (FpiDeviceGoodixMilanl *self)
{
  if (self->conn)
    g_socket_close (g_socket_connection_get_socket (self->conn), NULL);
  g_clear_object (&self->conn);
}

static void
session_free (Session *session)
{
  g_assert_cmpuint (session->pending_io, ==, 0);
  g_clear_error (&session->io_error);
  g_clear_object (&session->cancellable);
  g_clear_pointer (&session->request, g_byte_array_unref);
  g_clear_pointer (&session->response, g_free);
  g_clear_pointer (&session->blob, g_bytes_unref);
  g_free (session);
}

static guint8
session_opcode (FpDevice *device)
{
  switch (fpi_device_get_current_action (device))
    {
    case FPI_DEVICE_ACTION_OPEN:
      return GOODIX_MILANL_OP_HELLO;

    case FPI_DEVICE_ACTION_ENROLL:
      return GOODIX_MILANL_OP_ENROLL_BEGIN;

    case FPI_DEVICE_ACTION_VERIFY:
      return GOODIX_MILANL_OP_VERIFY;

    case FPI_DEVICE_ACTION_IDENTIFY:
      return GOODIX_MILANL_OP_IDENTIFY;

    case FPI_DEVICE_ACTION_NONE:
    case FPI_DEVICE_ACTION_PROBE:
    case FPI_DEVICE_ACTION_CLOSE:
    case FPI_DEVICE_ACTION_CAPTURE:
    case FPI_DEVICE_ACTION_LIST:
    case FPI_DEVICE_ACTION_DELETE:
    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
    default:
      g_assert_not_reached ();
    }
}

static gboolean
session_interrupted (FpiSsm *ssm)
{
  Session *session = fpi_ssm_get_data (ssm);

  if (g_cancellable_is_cancelled (session->cancellable) ||
      fpi_device_action_is_cancelled (fpi_ssm_get_device (ssm)))
    {
      fpi_ssm_mark_failed (ssm, cancelled_error ());
      return TRUE;
    }
  return FALSE;
}

static gboolean
prepare_request (FpDevice *device, Session *session, GError **error)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);
  guint32 length;

  g_clear_pointer (&session->request, g_byte_array_unref);
  session->request_written = FALSE;
  session->request = g_byte_array_new ();
  put_u32 (session->request, 0); /* Frame length, filled in below. */
  put_u8 (session->request, session->opcode);

  switch (session->opcode)
    {
    case GOODIX_MILANL_OP_HELLO:
      put_u32 (session->request, GOODIX_MILANL_PROTO_VERSION);
      break;

    case GOODIX_MILANL_OP_VERIFY:
      {
        FpPrint *print;
        g_autoptr(GBytes) blob = NULL;

        fpi_device_get_verify_data (device, &print);
        blob = blob_from_print (device, print);
        if (!blob)
          goto invalid_print;
        put_blob (session->request, blob);
        break;
      }

    case GOODIX_MILANL_OP_IDENTIFY:
      {
        GPtrArray *gallery;

        if (!(self->features & GOODIX_MILANL_FEAT_IDENTIFY))
          {
            *error = fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED);
            return FALSE;
          }
        fpi_device_get_identify_data (device, &gallery);
        if (gallery->len > GOODIX_MILANL_MAX_GALLERY)
          goto invalid_print;
        put_u16 (session->request, gallery->len);
        for (guint i = 0; i < gallery->len; i++)
          {
            g_autoptr(GBytes) blob = blob_from_print (device, g_ptr_array_index (gallery, i));

            /* Reject the gallery rather than filtering/reindexing or truncating it. */
            if (!blob)
              goto invalid_print;
            put_blob (session->request, blob);
          }
        break;
      }

    default:
      break;
    }

  if (session->request->len - 4 > GOODIX_MILANL_MAX_MESSAGE)
    goto invalid_print;
  length = GUINT32_TO_LE (session->request->len - 4);
  memcpy (session->request->data, &length, sizeof (length));
  return TRUE;

invalid_print:
  *error = fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                    "Invalid template or gallery exceeds protocol limits");
  return FALSE;
}

/* The same SSM owns the action across suspend/resume, including any terminal
 * result received before the SUSPEND acknowledgement. */
static void
continue_session (FpiSsm *ssm)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (fpi_ssm_get_device (ssm));
  Session *session = fpi_ssm_get_data (ssm);

  if (session_interrupted (ssm))
    return;
  if (self->suspend_requested)
    {
      session->opcode = GOODIX_MILANL_OP_SUSPEND;
      fpi_ssm_jump_to_state (ssm, session->suspend_sent ? SESSION_READ_HEADER : SESSION_WRITE);
    }
  else if (session->terminal)
    fpi_ssm_mark_completed (ssm);
  else
    {
      session->opcode = session->resume_opcode;
      fpi_ssm_jump_to_state (ssm, SESSION_WRITE);
    }
}

static void
process_response (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);
  Session *session = fpi_ssm_get_data (ssm);
  Cursor c = { session->response, session->response_len, 0, TRUE };
  guint8 result = get_u8 (&c);

  if (result == GOODIX_MILANL_R_ERROR)
    {
      guint8 reason = get_u8 (&c);

      if (!cursor_done (&c) || reason < GOODIX_MILANL_ERR_GENERAL || reason > GOODIX_MILANL_ERR_DATA)
        goto malformed;
      fpi_ssm_mark_failed (ssm, engine_error (reason));
      return;
    }

  if (result == GOODIX_MILANL_R_INTERRUPTED)
    {
      if (!cursor_done (&c) || !self->suspend_requested || !session->suspend_sent ||
          session->opcode < GOODIX_MILANL_OP_ENROLL_BEGIN ||
          session->opcode > GOODIX_MILANL_OP_IDENTIFY)
        goto malformed;
      continue_session (ssm);
      return;
    }

  switch (session->opcode)
    {
    case GOODIX_MILANL_OP_HELLO:
      {
        guint32 version = get_u32 (&c);
        guint16 stages = get_u16 (&c);
        guint32 features = get_u32 (&c);

        if (result != GOODIX_MILANL_R_HELLO || !cursor_done (&c) ||
            version != GOODIX_MILANL_PROTO_VERSION || stages == 0)
          goto malformed;
        self->enroll_stages = stages;
        self->features = features;
        fpi_device_set_nr_enroll_stages (device, stages);
        if (fpi_device_get_current_action (device) == FPI_DEVICE_ACTION_OPEN)
          fpi_ssm_mark_completed (ssm);
        else
          continue_session (ssm);
        return;
      }

    case GOODIX_MILANL_OP_ENROLL_BEGIN:
      if (result != GOODIX_MILANL_R_OK || !cursor_done (&c))
        goto malformed;
      session->resume_opcode = GOODIX_MILANL_OP_ENROLL_CAPTURE;
      continue_session (ssm);
      return;

    case GOODIX_MILANL_OP_SUSPEND:
      if (result != GOODIX_MILANL_R_OK || !cursor_done (&c))
        goto malformed;
      fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
      if (session_interrupted (ssm))
        return;
      session->suspend_sent = FALSE;
      self->suspend_requested = FALSE;
      self->paused = TRUE;
      fpi_device_suspend_complete (device, NULL);
      /* No callbacks remain. Keep this SSM and its result until resume/cancel. */
      return;

    case GOODIX_MILANL_OP_RESUME:
      if (result != GOODIX_MILANL_R_OK || !cursor_done (&c))
        goto malformed;
      self->resuming = FALSE;
      session->resumed_stage = TRUE;
      fpi_device_resume_complete (device, NULL);
      continue_session (ssm);
      return;

    case GOODIX_MILANL_OP_ENROLL_CAPTURE:
      if (result == GOODIX_MILANL_R_ENROLL_STAGE)
        {
          guint16 done = get_u16 (&c);

          if (!cursor_done (&c) || done == 0 || done >= self->enroll_stages ||
              (!session->resumed_stage && done != session->completed + 1))
            goto malformed;
          session->resumed_stage = FALSE;
          session->completed = done;
          fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
          if (session_interrupted (ssm))
            return;
          fpi_device_enroll_progress (device, done, NULL, NULL);
          continue_session (ssm);
          return;
        }
      if (result == GOODIX_MILANL_R_RETRY)
        {
          guint8 reason = get_u8 (&c);

          if (!cursor_done (&c) || reason < GOODIX_MILANL_RETRY_GENERAL || reason > GOODIX_MILANL_RETRY_CENTER)
            goto malformed;
          fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
          if (session_interrupted (ssm))
            return;
          fpi_device_enroll_progress (device, session->completed, NULL, retry_error (reason));
          continue_session (ssm);
          return;
        }
      if (result != GOODIX_MILANL_R_ENROLL_DONE)
        goto malformed;
      session->blob = get_blob (&c);
      if (!cursor_done (&c) ||
          (!session->resumed_stage && session->completed + 1 != self->enroll_stages))
        goto malformed;
      session->terminal = TRUE;
      continue_session (ssm);
      return;

    case GOODIX_MILANL_OP_VERIFY:
    case GOODIX_MILANL_OP_IDENTIFY:
      if (result == GOODIX_MILANL_R_MATCH)
        {
          guint16 index = get_u16 (&c);
          guint8 has_update = get_u8 (&c);

          if (has_update > 1)
            goto malformed;
          if (has_update)
            session->blob = get_blob (&c);
          if (!cursor_done (&c))
            goto malformed;
          if (session->opcode == GOODIX_MILANL_OP_VERIFY)
            {
              if (index != 0xffff)
                goto malformed;
              fpi_device_get_verify_data (device, &session->match);
            }
          else
            {
              GPtrArray *gallery;

              fpi_device_get_identify_data (device, &gallery);
              if (index >= gallery->len)
                goto malformed;
              session->match = g_ptr_array_index (gallery, index);
            }
        }
      else if (result == GOODIX_MILANL_R_RETRY)
        {
          session->retry = get_u8 (&c);
          if (session->retry < GOODIX_MILANL_RETRY_GENERAL || session->retry > GOODIX_MILANL_RETRY_CENTER)
            goto malformed;
        }
      else if (result != GOODIX_MILANL_R_NO_MATCH)
        goto malformed;
      if (!cursor_done (&c))
        goto malformed;
      session->result = result;
      session->terminal = TRUE;
      continue_session (ssm);
      return;

    default:
      g_assert_not_reached ();
    }

malformed:
  fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                    "Malformed engine response to opcode %u",
                                                    session->opcode));
}

/* A response read and the in-flight SUSPEND write may coexist. Drain both
 * callbacks before advancing or freeing the SSM, including on cancellation. */
static void
session_io_done (FpiSsm *ssm, GError *error)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (fpi_ssm_get_device (ssm));
  Session *session = fpi_ssm_get_data (ssm);

  g_assert_cmpuint (session->pending_io, >, 0);
  session->pending_io--;
  if (error)
    {
      if (!session->io_error)
        session->io_error = g_steal_pointer (&error);
      g_clear_error (&error);
      g_cancellable_cancel (session->cancellable);
      disconnect_engine (self);
    }
  if (session->pending_io)
    return;
  if (session->io_error)
    fpi_ssm_mark_failed (ssm, g_steal_pointer (&session->io_error));
  else
    fpi_ssm_next_state (ssm);
}

static void
connect_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (fpi_ssm_get_device (ssm));
  Session *session = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  self->conn = g_socket_client_connect_finish (G_SOCKET_CLIENT (source), result, &error);
  session->opcode = GOODIX_MILANL_OP_HELLO;
  session_io_done (ssm, error);
}

static void
write_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  Session *session = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  session->request_written = g_output_stream_write_all_finish (G_OUTPUT_STREAM (source), result,
                                                              NULL, &error);
  session_io_done (ssm, error);
}

static void
suspend_write_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
  GError *error = NULL;

  g_output_stream_write_all_finish (G_OUTPUT_STREAM (source), result, NULL, &error);
  session_io_done (user_data, error);
}

static void
send_suspend (FpiSsm *ssm)
{
  static const guint8 frame[] = { 1, 0, 0, 0, GOODIX_MILANL_OP_SUSPEND };
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (fpi_ssm_get_device (ssm));
  Session *session = fpi_ssm_get_data (ssm);
  gint state = fpi_ssm_get_cur_state (ssm);

  if (!self->suspend_requested || session->suspend_sent || !session->request_written ||
      !session->pending_io || session->io_error ||
      g_cancellable_is_cancelled (session->cancellable) ||
      (state != SESSION_READ_HEADER && state != SESSION_READ_BODY) ||
      session->opcode < GOODIX_MILANL_OP_ENROLL_BEGIN || session->opcode > GOODIX_MILANL_OP_IDENTIFY)
    return;
  session->suspend_sent = TRUE;
  session->pending_io++;
  g_output_stream_write_all_async (g_io_stream_get_output_stream (G_IO_STREAM (self->conn)),
                                   frame, sizeof (frame), G_PRIORITY_DEFAULT,
                                   session->cancellable, suspend_write_cb, ssm);
}

static void
read_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
  FpiSsm *ssm = user_data;
  Session *session = fpi_ssm_get_data (ssm);
  GError *error = NULL;
  gsize n;
  gsize expected = fpi_ssm_get_cur_state (ssm) == SESSION_READ_HEADER ? 4 : session->response_len;

  if (g_input_stream_read_all_finish (G_INPUT_STREAM (source), result, &n, &error) && n != expected)
    error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT,
                                 "Truncated engine response frame");
  session_io_done (ssm, error);
}

static void
session_run (FpiSsm *ssm, FpDevice *device)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);
  Session *session = fpi_ssm_get_data (ssm);
  GError *error = NULL;

  if (fpi_ssm_get_cur_state (ssm) == SESSION_START)
    {
      /* Yield even for local validation failures, before any *Start results. */
      fpi_ssm_next_state_delayed (ssm, 0);
      return;
    }
  if (session_interrupted (ssm))
    return;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case SESSION_CONNECT:
      if (self->conn)
        fpi_ssm_next_state (ssm);
      else
        {
          g_autoptr(GSocketClient) client = g_socket_client_new ();
          g_autoptr(GSocketAddress) addr = NULL;
          const gchar *path = fpi_device_get_virtual_env (device);

          if (!path || !*path)
            {
              fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                                "GOODIX_MILANL_ENGINE is unset"));
              return;
            }
          addr = g_unix_socket_address_new (path);
          session->pending_io++;
          g_socket_client_connect_async (client, G_SOCKET_CONNECTABLE (addr),
                                         session->cancellable, connect_cb, ssm);
        }
      break;

    case SESSION_WRITE:
      if (!prepare_request (device, session, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      if (session->opcode == GOODIX_MILANL_OP_ENROLL_CAPTURE ||
          session->opcode == GOODIX_MILANL_OP_VERIFY || session->opcode == GOODIX_MILANL_OP_IDENTIFY)
        {
          /* The protocol reports pending captures, not live finger-down/up events. */
          fpi_device_report_finger_status (device, FP_FINGER_STATUS_NEEDED);
          if (session_interrupted (ssm))
            return;
        }
      session->pending_io++;
      g_output_stream_write_all_async (g_io_stream_get_output_stream (G_IO_STREAM (self->conn)),
                                       session->request->data, session->request->len,
                                       G_PRIORITY_DEFAULT, session->cancellable, write_cb, ssm);
      break;

    case SESSION_READ_HEADER:
      g_clear_pointer (&session->response, g_free);
      session->pending_io++;
      g_input_stream_read_all_async (g_io_stream_get_input_stream (G_IO_STREAM (self->conn)),
                                     session->header, sizeof (session->header),
                                     G_PRIORITY_DEFAULT, session->cancellable, read_cb, ssm);
      send_suspend (ssm);
      break;

    case SESSION_READ_BODY:
      {
        Cursor c = { session->header, sizeof (session->header), 0, TRUE };

        session->response_len = get_u32 (&c);
        if (session->response_len == 0 || session->response_len > GOODIX_MILANL_MAX_MESSAGE)
          {
            fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "Engine frame length out of range"));
            return;
          }
        session->response = g_malloc (session->response_len);
        session->pending_io++;
        g_input_stream_read_all_async (g_io_stream_get_input_stream (G_IO_STREAM (self->conn)),
                                       session->response, session->response_len,
                                       G_PRIORITY_DEFAULT, session->cancellable, read_cb, ssm);
        send_suspend (ssm);
        break;
      }

    case SESSION_RESPONSE:
      process_response (ssm, device);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
complete_action (FpDevice *device, Session *session)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);
  FpiDeviceAction action = fpi_device_get_current_action (device);
  FpPrint *print = NULL;

  fpi_device_report_finger_status (device, FP_FINGER_STATUS_NONE);
  if (fpi_device_action_is_cancelled (device))
    goto cancelled;

  if (action == FPI_DEVICE_ACTION_OPEN)
    {
      fpi_device_open_complete (device, NULL);
      return;
    }
  if (action == FPI_DEVICE_ACTION_ENROLL)
    {
      fpi_device_enroll_progress (device, self->enroll_stages, NULL, NULL);
      if (fpi_device_action_is_cancelled (device))
        goto cancelled;
      fpi_device_get_enroll_data (device, &print);
      fpi_print_set_type (print, FPI_PRINT_RAW);
      set_print_blob (print, session->blob);
    }
  else
    {
      /* Validate the entire MATCH before mutating, and adapt the exact gallery
       * object before the report callback (fprintd persists it separately). */
      if (session->blob)
        set_print_blob (session->match, session->blob);
      if (fpi_device_action_is_cancelled (device))
        goto cancelled;
      if (action == FPI_DEVICE_ACTION_VERIFY)
        fpi_device_verify_report (device,
                                  session->result == GOODIX_MILANL_R_MATCH ? FPI_MATCH_SUCCESS :
                                  session->result == GOODIX_MILANL_R_NO_MATCH ? FPI_MATCH_FAIL : FPI_MATCH_ERROR,
                                  NULL, session->retry ? retry_error (session->retry) : NULL);
      else
        fpi_device_identify_report (device, session->match, NULL,
                                    session->retry ? retry_error (session->retry) : NULL);
    }

  if (fpi_device_action_is_cancelled (device))
    goto cancelled;
  if (action == FPI_DEVICE_ACTION_ENROLL)
    fpi_device_enroll_complete (device, g_object_ref (print), NULL);
  else if (action == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (device, NULL);
  else
    fpi_device_identify_complete (device, NULL);
  return;

cancelled:
  disconnect_engine (self);
  fpi_device_action_error (device, cancelled_error ());
}

static void
session_done (FpiSsm *ssm, FpDevice *device, GError *error)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);
  Session *session = fpi_ssm_get_data (ssm);

  self->ssm = NULL;
  if (fpi_device_action_is_cancelled (device))
    {
      g_clear_error (&error);
      error = cancelled_error ();
    }
  if (error)
    disconnect_engine (self);

  self->paused = FALSE;
  if (self->suspend_requested)
    {
      self->suspend_requested = FALSE;
      fpi_device_suspend_complete (device, g_error_copy (error));
    }
  if (self->resuming)
    {
      self->resuming = FALSE;
      fpi_device_resume_complete (device, g_error_copy (error));
    }

  if (error)
    fpi_device_action_error (device, error);
  else
    complete_action (device, session);
}

static void
start_session (FpDevice *device)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);
  Session *session = g_new0 (Session, 1);

  session->opcode = session_opcode (device);
  session->resume_opcode = session->opcode;
  session->cancellable = g_cancellable_new ();
  self->ssm = fpi_ssm_new (device, session_run, SESSION_NUM_STATES);
  fpi_ssm_set_data (self->ssm, session, (GDestroyNotify) session_free);
  fpi_ssm_start (self->ssm, session_done);
}

static void
dev_start (FpDevice *device)
{
  start_session (device);
}

static void
dev_close (FpDevice *device)
{
  disconnect_engine (FPI_DEVICE_GOODIX_MILANL (device));
  fpi_device_close_complete (device, NULL);
}

static void
dev_cancel (FpDevice *device)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);

  disconnect_engine (self);
  if (self->ssm)
    {
      Session *session = fpi_ssm_get_data (self->ssm);

      g_cancellable_cancel (session->cancellable);
      /* An active callback (or the START idle) owns completion. A paused SSM
       * has neither, so cancellation finishes it here and drops saved results. */
      if (self->paused)
        fpi_ssm_mark_failed (self->ssm, cancelled_error ());
    }
}

static void
dev_suspend (FpDevice *device)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);

  /* A result already being reported cannot be held back for resume. */
  if (!self->ssm)
    {
      fpi_device_suspend_complete (device, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      return;
    }
  self->suspend_requested = TRUE;
  send_suspend (self->ssm);
}

static void
dev_resume (FpDevice *device)
{
  FpiDeviceGoodixMilanl *self = FPI_DEVICE_GOODIX_MILANL (device);
  Session *session = fpi_ssm_get_data (self->ssm);

  self->paused = FALSE;
  self->resuming = TRUE;
  session->opcode = GOODIX_MILANL_OP_RESUME;
  fpi_ssm_jump_to_state (self->ssm, SESSION_START);
}

static void
dev_finalize (GObject *object)
{
  disconnect_engine (FPI_DEVICE_GOODIX_MILANL (object));
  G_OBJECT_CLASS (fpi_device_goodix_milanl_parent_class)->finalize (object);
}

static const FpIdEntry id_table[] = {
  { .virtual_envvar = "GOODIX_MILANL_ENGINE", },
  { .virtual_envvar = NULL }
};

static void
fpi_device_goodix_milanl_init (FpiDeviceGoodixMilanl *self)
{
  self->enroll_stages = DEFAULT_ENROLL_STAGES;
}

static void
fpi_device_goodix_milanl_class_init (FpiDeviceGoodixMilanlClass *klass)
{
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  G_OBJECT_CLASS (klass)->finalize = dev_finalize;
  dev_class->id = "goodix_milanl";
  dev_class->full_name = "Goodix MilanL (SGX engine)";
  dev_class->type = FP_DEVICE_TYPE_VIRTUAL;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->id_table = id_table;
  dev_class->nr_enroll_stages = DEFAULT_ENROLL_STAGES;
  dev_class->temp_hot_seconds = -1;

  dev_class->open = dev_start;
  dev_class->close = dev_close;
  dev_class->enroll = dev_start;
  dev_class->verify = dev_start;
  dev_class->identify = dev_start;
  dev_class->cancel = dev_cancel;
  dev_class->suspend = dev_suspend;
  dev_class->resume = dev_resume;

  fpi_device_class_auto_initialize_features (dev_class);
}
