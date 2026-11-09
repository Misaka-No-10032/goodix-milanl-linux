/* Public libfprint API integration client for test_goodix_milanl_driver_async.py. */
#include <libfprint/fprint.h>
#include <string.h>

static const char *original_blob = "goodix-milanl-driver-test-template";
static const char *verify_blob = "goodix-milanl-driver-verify-update";
static const char *identify_blob = "goodix-milanl-driver-identify-update";
static const char *test_case;
static guint beats;
static guint needed;
static GCancellable *cancel_on_needed;

typedef enum { OPEN, ENROLL, VERIFY, IDENTIFY, SUSPEND, RESUME } Operation;

typedef struct
{
  Operation     op;
  FpDevice     *device;
  GCancellable *cancel;
  gboolean      returned;
  gboolean      done;
  gboolean      success;
  gboolean      matched;
  GError       *error;
  FpPrint      *print;
  FpPrint      *match;
  FpPrint      *expected_match;
  const char   *expected_blob;
  guint         reports;
  guint         stages;
  guint         retries;
  guint         cancel_stage;
  gboolean      cancel_report;
  gboolean      allow_stage_reset;
} Result;

static void
assert_blob (FpPrint *print, const char *expected)
{
  g_autoptr(GVariant) value = NULL;
  gsize len;
  const guint8 *data;

  g_object_get (print, "fpi-data", &value, NULL);
  g_assert_nonnull (value);
  g_assert_true (g_variant_is_of_type (value, G_VARIANT_TYPE ("ay")));
  data = g_variant_get_fixed_array (value, &len, 1);
  g_assert_cmpmem (data, len, expected, strlen (expected));
}

static FpPrint *
copy_print (FpPrint *print)
{
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *data = NULL;
  gsize len;
  FpPrint *copy;

  g_assert_true (fp_print_serialize (print, &data, &len, &error));
  g_assert_no_error (error);
  copy = fp_print_deserialize (data, len, &error);
  g_assert_no_error (error);
  g_assert_nonnull (copy);
  return copy;
}

static gboolean
heartbeat (gpointer unused)
{
  beats++;
  return G_SOURCE_CONTINUE;
}

static void
finger_status (FpDevice *device, GParamSpec *spec, gpointer unused)
{
  if (fp_device_get_finger_status (device) & FP_FINGER_STATUS_NEEDED)
    {
      needed++;
      if (cancel_on_needed)
        g_cancellable_cancel (cancel_on_needed);
    }
}

static void
finished (GObject *source, GAsyncResult *async, gpointer user_data)
{
  Result *r = user_data;

  g_assert_true (r->returned);
  g_assert_false (r->done);
  switch (r->op)
    {
    case OPEN:
      r->success = fp_device_open_finish (r->device, async, &r->error);
      break;
    case ENROLL:
      r->print = fp_device_enroll_finish (r->device, async, &r->error);
      r->success = r->print != NULL;
      break;
    case VERIFY:
      r->success = fp_device_verify_finish (r->device, async, &r->matched, NULL, &r->error);
      break;
    case IDENTIFY:
      r->success = fp_device_identify_finish (r->device, async, &r->match, NULL, &r->error);
      r->matched = r->match != NULL;
      break;
    case SUSPEND:
      r->success = fp_device_suspend_finish (r->device, async, &r->error);
      break;
    case RESUME:
      r->success = fp_device_resume_finish (r->device, async, &r->error);
      break;
    }
  r->done = TRUE;
}

static void
progress (FpDevice *device, gint completed, FpPrint *print, gpointer user_data, GError *error)
{
  Result *r = user_data;

  g_assert_true (r->returned);
  if (error)
    {
      g_assert_error (error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_CENTER_FINGER);
      g_assert_cmpuint (completed, ==, r->stages);
      r->retries++;
    }
  else
    {
      g_assert_cmpuint (completed, ==, r->allow_stage_reset ? 1 : r->stages + 1);
      r->allow_stage_reset = FALSE;
      r->stages = completed;
      if (r->cancel_stage == r->stages)
        g_cancellable_cancel (r->cancel);
    }
}

static void
reported (FpDevice *device, FpPrint *match, FpPrint *print, gpointer user_data, GError *error)
{
  Result *r = user_data;

  g_assert_true (r->returned);
  g_assert_cmpuint (r->reports++, ==, 0);
  if (r->expected_match)
    g_assert_true (match == r->expected_match);
  if (r->expected_blob)
    {
      g_autoptr(FpPrint) persisted = NULL;

      assert_blob (match, r->expected_blob);
      /* The adaptation must already be serializable inside the report callback. */
      persisted = copy_print (match);
      assert_blob (persisted, r->expected_blob);
    }
  if (r->cancel_report)
    g_cancellable_cancel (r->cancel);
}

static void
wait_result (Result *r)
{
  while (!r->done)
    g_main_context_iteration (NULL, TRUE);
}

static void
clear_result (Result *r)
{
  g_clear_error (&r->error);
  g_clear_object (&r->print);
  g_clear_object (&r->match);
  *r = (Result) { 0 };
}

static void
assert_success (Result *r)
{
  wait_result (r);
  g_assert_no_error (r->error);
  g_assert_true (r->success);
}

static void
assert_cancelled (Result *r)
{
  wait_result (r);
  g_assert_false (r->success);
  g_assert_error (r->error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
}

static void
start_open (Result *r, FpDevice *device, GCancellable *cancel)
{
  r->op = OPEN;
  r->device = device;
  fp_device_open (device, cancel, finished, r);
  r->returned = TRUE;
}

static void
start_enroll (Result *r, FpDevice *device, GCancellable *cancel)
{
  FpPrint *print = fp_print_new (device);

  fp_print_set_finger (print, FP_FINGER_RIGHT_INDEX);
  fp_print_set_username (print, "driver-test");
  r->op = ENROLL;
  r->device = device;
  r->cancel = cancel;
  fp_device_enroll (device, print, cancel, progress, r, NULL, finished, r);
  r->returned = TRUE;
}

static void
start_match (Result *r, FpDevice *device, FpPrint *print, GPtrArray *gallery,
             GCancellable *cancel)
{
  r->op = gallery ? IDENTIFY : VERIFY;
  r->device = device;
  r->cancel = cancel;
  if (gallery)
    fp_device_identify (device, gallery, cancel, reported, r, NULL, finished, r);
  else
    fp_device_verify (device, print, cancel, reported, r, NULL, finished, r);
  r->returned = TRUE;
}

static void
start_power (Result *r, FpDevice *device, Operation op)
{
  r->op = op;
  r->device = device;
  if (op == SUSPEND)
    fp_device_suspend (device, NULL, finished, r);
  else
    fp_device_resume (device, NULL, finished, r);
  r->returned = TRUE;
}

static gboolean
cancel_later (gpointer cancel)
{
  g_cancellable_cancel (cancel);
  return G_SOURCE_REMOVE;
}

static gboolean
suspend_later (gpointer data)
{
  Result *r = data;

  start_power (r, r->device, SUSPEND);
  return G_SOURCE_REMOVE;
}

static void
healthy_verify (FpDevice *device, FpPrint *print)
{
  Result r = { .expected_match = print };

  start_match (&r, device, print, NULL, NULL);
  assert_success (&r);
  g_assert_true (r.matched);
  g_assert_cmpuint (r.reports, ==, 1);
  g_assert_cmpuint (fp_device_get_finger_status (device), ==, FP_FINGER_STATUS_NONE);
  clear_result (&r);
}

static void
invalid_gallery (FpDevice *device, FpPrint *stored)
{
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  g_autoptr(FpPrint) large = copy_print (stored);
  g_autofree guint8 *bytes = g_malloc0 (1024 * 1024 + 1);
  Result r = { 0 };

  g_ptr_array_add (gallery, g_object_ref_sink (fp_print_new (device)));
  g_ptr_array_add (gallery, g_object_ref (stored));
  start_match (&r, device, NULL, gallery, NULL);
  wait_result (&r);
  g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  g_assert_cmpuint (r.reports, ==, 0);
  clear_result (&r);

  g_ptr_array_set_size (gallery, 0);
  for (guint i = 0; i < 17; i++)
    g_ptr_array_add (gallery, g_object_ref (stored));
  start_match (&r, device, NULL, gallery, NULL);
  wait_result (&r);
  g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  clear_result (&r);

  g_object_set (large, "fpi-data", g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bytes, 1024 * 1024 + 1, 1), NULL);
  g_ptr_array_set_size (gallery, 0);
  g_ptr_array_add (gallery, g_object_ref (large));
  start_match (&r, device, NULL, gallery, NULL);
  wait_result (&r);
  g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  clear_result (&r);
  healthy_verify (device, stored);
}

int
main (int argc, char **argv)
{
  g_autoptr(FpContext) context = NULL;
  g_autoptr(FpPrint) stored = NULL;
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  g_autoptr(GPtrArray) gallery = g_ptr_array_new_with_free_func (g_object_unref);
  g_autoptr(GError) error = NULL;
  FpDevice *device = NULL;
  Result r = { 0 }, power = { 0 }, resumed = { 0 };
  guint start_beats;
  guint timer;

  g_assert_cmpint (argc, ==, 2);
  test_case = argv[1];
  context = fp_context_new ();
  fp_context_enumerate (context);
  GPtrArray *devices = fp_context_get_devices (context);
  for (guint i = 0; i < devices->len; i++)
    if (g_str_equal (fp_device_get_driver (g_ptr_array_index (devices, i)), "goodix_milanl"))
      device = g_ptr_array_index (devices, i);
  g_assert_nonnull (device);
  g_assert_false (fp_device_has_feature (device, FP_DEVICE_FEATURE_STORAGE));
  g_signal_connect (device, "notify::finger-status", G_CALLBACK (finger_status), NULL);
  timer = g_timeout_add (5, heartbeat, NULL);

  start_open (&r, device, cancel);
  if (g_str_equal (test_case, "cancel-open"))
    {
      g_timeout_add (100, cancel_later, cancel);
      assert_cancelled (&r);
      g_assert_cmpuint (beats, >=, 5);
      clear_result (&r);
      g_cancellable_reset (cancel);
      start_open (&r, device, cancel);
    }
  if (g_str_equal (test_case, "malformed-hello"))
    {
      wait_result (&r);
      g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      clear_result (&r);
      start_open (&r, device, NULL);
    }
  assert_success (&r);
  if (g_str_equal (test_case, "delay"))
    g_assert_cmpuint (beats, >=, 5);
  g_assert_cmpint (fp_device_get_nr_enroll_stages (device), ==, 12);
  clear_result (&r);

  if (g_str_equal (test_case, "suspend-connect") || g_str_equal (test_case, "suspend-hello"))
    {
      /* Force the next action through connect/HELLO without closing the device. */
      start_enroll (&r, device, cancel);
      g_cancellable_cancel (cancel);
      assert_cancelled (&r);
      clear_result (&r);
      g_cancellable_reset (cancel);
    }
  if (g_str_equal (test_case, "cancel-progress"))
    r.cancel_stage = 1;
  if (g_str_equal (test_case, "cancel-final"))
    r.cancel_stage = 12;
  start_enroll (&r, device, cancel);
  if (g_str_equal (test_case, "cancel-enroll"))
    g_timeout_add (100, cancel_later, cancel);
  if (g_str_has_prefix (test_case, "suspend-enroll") ||
      g_str_equal (test_case, "suspend-before") || g_str_equal (test_case, "suspend-begin") ||
      g_str_equal (test_case, "suspend-connect") || g_str_equal (test_case, "suspend-hello"))
    {
      power.device = device;
      if (g_str_equal (test_case, "suspend-before") || g_str_equal (test_case, "suspend-connect"))
        start_power (&power, device, SUSPEND);
      else
        g_timeout_add (100, suspend_later, &power);
      assert_success (&power);
      g_assert_false (r.done);
      g_assert_cmpuint (fp_device_get_finger_status (device), ==, FP_FINGER_STATUS_NONE);
      if (g_str_equal (test_case, "suspend-enroll") || g_str_equal (test_case, "suspend-enroll-stage"))
        g_assert_cmpuint (r.stages, ==, 2);
      if (g_str_equal (test_case, "suspend-enroll-late"))
        g_assert_cmpuint (r.stages, ==, 3);
      if (g_str_equal (test_case, "suspend-enroll-final") || g_str_equal (test_case, "suspend-enroll-reset"))
        g_assert_cmpuint (r.stages, ==, 11);
      r.allow_stage_reset = g_str_equal (test_case, "suspend-enroll-reset");
      start_power (&resumed, device, RESUME);
      assert_success (&resumed);
      if (g_str_equal (test_case, "suspend-enroll-late"))
        {
          wait_result (&r);
          g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_GENERAL);
          g_assert_null (r.print);
          clear_result (&r);
          start_enroll (&r, device, cancel);
        }
    }
  if (g_str_equal (test_case, "cancel-enroll") || g_str_equal (test_case, "cancel-progress") ||
      g_str_equal (test_case, "cancel-final"))
    {
      assert_cancelled (&r);
      clear_result (&r);
      g_cancellable_reset (cancel);
      start_enroll (&r, device, cancel);
    }
  if (g_str_equal (test_case, "malformed-enroll"))
    {
      wait_result (&r);
      g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      g_assert_null (r.print);
      clear_result (&r);
      start_enroll (&r, device, cancel);
    }
  assert_success (&r);
  g_assert_cmpuint (r.stages, ==, 12);
  if (g_str_equal (test_case, "roundtrip"))
    g_assert_cmpuint (r.retries, ==, 1);
  stored = copy_print (r.print);
  assert_blob (stored, original_blob);
  clear_result (&r);
  clear_result (&power);
  clear_result (&resumed);
  g_ptr_array_add (gallery, copy_print (stored));
  g_ptr_array_add (gallery, g_object_ref (stored));

  if (g_str_equal (test_case, "invalid-gallery"))
    {
      invalid_gallery (device, stored);
      goto out;
    }

  if (g_str_equal (test_case, "suspend-write") || g_str_equal (test_case, "max-gallery"))
    {
      g_autoptr(FpPrint) large = copy_print (stored);
      gsize length = g_str_equal (test_case, "max-gallery") ? 1024 * 1024 : 65536;
      g_autofree guint8 *bytes = g_malloc (length);

      memset (bytes, 'w', length);
      g_object_set (large, "fpi-data", g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bytes, length, 1), NULL);
      g_ptr_array_set_size (gallery, 0);
      for (guint i = 0; i < 16; i++)
        g_ptr_array_add (gallery, g_object_ref (large));
    }
  if (g_str_equal (test_case, "roundtrip") || g_str_equal (test_case, "suspend-match"))
    r.expected_blob = verify_blob;
  if (g_str_equal (test_case, "suspend-identify-match"))
    {
      r.expected_blob = identify_blob;
      r.expected_match = stored;
    }
  r.cancel_report = g_str_equal (test_case, "cancel-report");
  if (g_str_equal (test_case, "cancel-needed"))
    cancel_on_needed = cancel;
  start_beats = beats;
  start_match (&r, device, stored,
               g_str_equal (test_case, "suspend-identify") ||
               g_str_equal (test_case, "suspend-identify-match") ||
               g_str_equal (test_case, "suspend-write") || g_str_equal (test_case, "max-gallery") ||
               g_str_equal (test_case, "malformed-identify") ? gallery : NULL, cancel);

  if (g_str_equal (test_case, "cancel"))
    g_timeout_add (100, cancel_later, cancel);
  if (g_str_equal (test_case, "cancel-before"))
    g_cancellable_cancel (cancel);

  if (g_str_equal (test_case, "suspend") || g_str_equal (test_case, "suspend-identify") ||
      g_str_equal (test_case, "cancel-paused") || g_str_equal (test_case, "cancel-suspend") ||
      g_str_equal (test_case, "cancel-resume") || g_str_equal (test_case, "suspend-error") ||
      g_str_equal (test_case, "resume-error") || g_str_equal (test_case, "suspend-match") ||
      g_str_equal (test_case, "suspend-identify-match") || g_str_equal (test_case, "cancel-saved") ||
      g_str_equal (test_case, "suspend-write"))
    {
      power.device = device;
      g_timeout_add (100, suspend_later, &power);
      if (g_str_equal (test_case, "cancel-suspend"))
        g_timeout_add (220, cancel_later, cancel);
      wait_result (&power);
      if (g_str_equal (test_case, "suspend-error"))
        {
          g_assert_error (power.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
          wait_result (&r);
          g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_BUSY);
        }
      else if (g_str_equal (test_case, "cancel-suspend"))
        {
          g_assert_error (power.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
          assert_cancelled (&r);
        }
      else
        {
          g_assert_no_error (power.error);
          g_assert_true (power.success);
          g_assert_false (r.done);
          g_assert_cmpuint (r.reports, ==, 0);
          assert_blob (stored, original_blob);
          g_assert_cmpuint (fp_device_get_finger_status (device), ==, FP_FINGER_STATUS_NONE);
          if (g_str_equal (test_case, "cancel-paused") || g_str_equal (test_case, "cancel-saved"))
            {
              g_cancellable_cancel (cancel);
              assert_cancelled (&r);
            }
        }
      start_power (&resumed, device, RESUME);
      if (g_str_equal (test_case, "cancel-resume"))
        g_timeout_add (100, cancel_later, cancel);
      wait_result (&resumed);
      if (g_str_equal (test_case, "cancel-resume"))
        {
          g_assert_error (resumed.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
          assert_cancelled (&r);
        }
      else if (g_str_equal (test_case, "resume-error"))
        {
          g_assert_error (resumed.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
          wait_result (&r);
          g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
        }
      else
        assert_success (&resumed);
      if (g_str_equal (test_case, "suspend") || g_str_equal (test_case, "suspend-identify") ||
          g_str_equal (test_case, "suspend-match") || g_str_equal (test_case, "suspend-identify-match") ||
          g_str_equal (test_case, "suspend-write"))
        {
          assert_success (&r);
          g_assert_true (r.matched);
          g_assert_cmpuint (r.reports, ==, 1);
        }
      g_assert_cmpuint (beats - start_beats, >=, 10);
      clear_result (&r);
      healthy_verify (device, stored);
      goto out;
    }

  if (g_str_equal (test_case, "cancel") || g_str_equal (test_case, "cancel-before") ||
      g_str_equal (test_case, "cancel-needed") || g_str_equal (test_case, "cancel-report"))
    {
      assert_cancelled (&r);
      g_assert_cmpuint (r.reports, ==, r.cancel_report ? 1 : 0);
      cancel_on_needed = NULL;
      if (g_str_equal (test_case, "cancel"))
        g_assert_cmpuint (beats - start_beats, >=, 5);
      clear_result (&r);
      healthy_verify (device, stored);
    }
  else if (g_str_has_prefix (test_case, "malformed") || g_str_equal (test_case, "truncated-frame"))
    {
      wait_result (&r);
      if (g_str_equal (test_case, "truncated-frame"))
        g_assert_error (r.error, G_IO_ERROR, G_IO_ERROR_PARTIAL_INPUT);
      else if (!g_str_equal (test_case, "malformed-hello") && !g_str_equal (test_case, "malformed-enroll"))
        g_assert_error (r.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
      if (g_str_equal (test_case, "malformed") || g_str_equal (test_case, "malformed-identify") ||
          g_str_equal (test_case, "truncated-frame"))
        g_assert_cmpuint (r.reports, ==, 0);
      assert_blob (stored, original_blob);
      clear_result (&r);
      healthy_verify (device, stored);
    }
  else if (g_str_equal (test_case, "retry"))
    {
      wait_result (&r);
      g_assert_error (r.error, FP_DEVICE_RETRY, FP_DEVICE_RETRY_TOO_SHORT);
      g_assert_cmpuint (r.reports, ==, 1);
    }
  else
    {
      assert_success (&r);
      g_assert_cmpuint (r.reports, ==, 1);
      g_assert_cmpint (r.matched, ==, !g_str_equal (test_case, "no-match"));
      if (g_str_equal (test_case, "delay"))
        g_assert_cmpuint (beats - start_beats, >=, 10);
      clear_result (&r);
      if (g_str_equal (test_case, "roundtrip"))
        {
          r.expected_match = stored;
          r.expected_blob = identify_blob;
          start_match (&r, device, NULL, gallery, NULL);
          assert_success (&r);
          g_assert_true (r.match == stored);
          assert_blob (g_ptr_array_index (gallery, 0), original_blob);
          assert_blob (stored, identify_blob);
        }
    }

out:
  g_assert_cmpuint (needed, >, 0);
  g_assert_cmpuint (fp_device_get_finger_status (device), ==, FP_FINGER_STATUS_NONE);
  g_assert_true (fp_device_close_sync (device, NULL, &error));
  g_assert_no_error (error);
  g_source_remove (timer);
  clear_result (&r);
  clear_result (&power);
  clear_result (&resumed);
  g_print ("PASS %s\n", test_case);
  return 0;
}
