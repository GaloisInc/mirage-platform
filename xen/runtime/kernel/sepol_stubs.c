/*
 * sepol_stubs.c --- Ocaml bindings to libsepol services.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 18 December 2013
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <sepol/sepol.h>
#include <sepol/policydb/services.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include <caml/bigarray.h>

/* TODO: Add a function to load policy from memory image. */

static sidtab_t g_sidtab;
static policydb_t g_policydb;

CAMLprim value sid_to_context(value sid)
{
  CAMLparam1(sid);

  CAMLlocal1(result);
  result = caml_alloc(2, 0);    /* int * string */

  sepol_security_context_t context;
  sepol_security_id_t c_sid = Int32_val(sid);
  size_t len;
  
  int rc = sepol_sid_to_context(c_sid, &context, &len);
  if (rc < 0) {
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, caml_copy_string(""));
  } else {
    Store_field(result, 0, Val_int(0));
    Store_field(result, 1, caml_copy_string(context));
    free(context);
  }

  CAMLreturn(result);
}

CAMLprim value context_to_sid(value context)
{
  CAMLparam1(context);

  CAMLlocal1(result);
  result = caml_alloc(2, 0);    /* int * int32 */

  sepol_security_id_t sid;
  char *c_context = String_val(context);

  int rc = sepol_context_to_sid(c_context, strlen(c_context), &sid);
  if (rc < 0) {
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, caml_copy_int32(0));
  } else {
    Store_field(result, 0, Val_int(0));
    Store_field(result, 1, caml_copy_int32(sid));
  }

  CAMLreturn(result);
}

CAMLprim value load_policy(value array)
{
  CAMLparam1(array);

  struct policy_file pf;
  policy_file_init(&pf);

  pf.type = PF_USE_MEMORY;
  pf.data = Caml_ba_data_val(array);
  pf.len  = Caml_ba_array_val(array)->dim[0];

  if (policydb_init(&g_policydb)) {
    caml_failwith("load_policy: out of memory");
    CAMLreturn(Val_unit);
  }

  if (policydb_read(&g_policydb, &pf, 0)) {
    policydb_destroy(&g_policydb);
    caml_failwith("load_policy: loading policy failed");
    CAMLreturn(Val_unit);
  }

  sepol_sidtab_init(&g_sidtab);
  sepol_set_policydb(&g_policydb);
  sepol_set_sidtab(&g_sidtab);
  policydb_load_isids(&g_policydb, &g_sidtab);

  CAMLreturn(Val_unit);
}

CAMLprim value check_context(value context)
{
  CAMLparam1(context);

  char *c_context = String_val(context);
  int result = sepol_check_context(c_context);

  CAMLreturn(Val_int(result));
}

CAMLprim value compute_av(value ssid, value tsid, value tclass, value av)
{
  CAMLparam4(ssid, tsid, tclass, av);

  CAMLlocal2(result, avd);
  result = caml_alloc(2, 0);    /* int * av_decision */
  avd    = caml_alloc(4, 0);    /* av_decision */

  struct sepol_av_decision c_avd;
  int rc;

  value c_ssid   = Int32_val(ssid);
  value c_tsid   = Int32_val(tsid);
  value c_tclass = Int32_val(tclass);
  value c_av     = Int32_val(av);

  rc = sepol_compute_av(c_ssid, c_tsid, c_tclass, c_av, &c_avd);

  Store_field(avd, 0, caml_copy_int32(c_avd.allowed));
  Store_field(avd, 1, caml_copy_int32(c_avd.decided));
  Store_field(avd, 2, caml_copy_int32(c_avd.auditallow));
  Store_field(avd, 3, caml_copy_int32(c_avd.auditdeny));

  Store_field(result, 0, Val_int(rc));
  Store_field(result, 1, avd);

  CAMLreturn(result);
}

CAMLprim value transition_sid(value ssid, value tsid, value tclass)
{
  CAMLparam3(ssid, tsid, tclass);

  CAMLlocal1(result);
  result = caml_alloc(2, 0);    /* int * int32 */

  value c_ssid   = Int32_val(ssid);
  value c_tsid   = Int32_val(tsid);
  value c_tclass = Int32_val(tclass);

  sepol_security_id_t c_sid;
  int rc = sepol_transition_sid(c_ssid, c_tsid, c_tclass, &c_sid);

  Store_field(result, 0, Val_int(rc));
  Store_field(result, 1, caml_copy_int32(c_sid));

  CAMLreturn(result);
}
