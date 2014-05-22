/*
 * Copyright (c) 2013, Galois, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Written by James Bielman <jamesjb@galois.com>, 25 July 2013
 */

#define __XEN_TOOLS__

#include <mini-os/x86/os.h>
#include <mini-os/hypervisor.h>
#include <xen/xen.h>
#include <xen/domctl.h>
#include <xen/xsm/flask_op.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/bigarray.h>
#include <caml/alloc.h>
#include <caml/fail.h>

CAMLprim value
caml_flask_context_to_sid(value context)
{
  CAMLparam1(context);

  xen_flask_op_t flask_op;
  char *c_context = String_val(context);

  flask_op.cmd = FLASK_CONTEXT_TO_SID;
  flask_op.interface_version = XEN_FLASK_INTERFACE_VERSION;
  flask_op.u.sid_context.size = caml_string_length(context);
  set_xen_guest_handle(flask_op.u.sid_context.context, c_context);

  CAMLlocal1(result);
  result = caml_alloc(2, 0);    /* int * int32 */

  int rc = HYPERVISOR_xsm_op(&flask_op);
  if (rc < 0) {
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, caml_copy_int32(0));
  } else {
    Store_field(result, 0, Val_int(0));
    Store_field(result, 1, caml_copy_int32(flask_op.u.sid_context.sid));
  }

  CAMLreturn(result);
}

CAMLprim value
caml_flask_sid_to_context(value sid)
{
  CAMLparam1(sid);

  xen_flask_op_t flask_op;

  /* TODO: What is the maximum length of a context? */
  char buf[1024];
  flask_op.cmd = FLASK_SID_TO_CONTEXT;
  flask_op.interface_version = XEN_FLASK_INTERFACE_VERSION;
  flask_op.u.sid_context.size = sizeof(buf);
  flask_op.u.sid_context.sid = Int32_val(sid);
  set_xen_guest_handle(flask_op.u.sid_context.context, buf);

  CAMLlocal1(result);
  result = caml_alloc(2, 0);    /* int * string */

  int rc = HYPERVISOR_xsm_op(&flask_op);
  if (rc < 0) {
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, caml_copy_string(""));
  } else {
    Store_field(result, 0, Val_int(0));
    Store_field(result, 1, caml_copy_string(buf));
  }

  CAMLreturn(result);
}

CAMLprim value
caml_flask_getdomainsid(value domid)
{
  CAMLparam1(domid);

  xen_domctl_t op;
  op.cmd = XEN_DOMCTL_getdomaininfo;
  op.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
  op.domain = Int_val(domid);

  CAMLlocal1(result);
  result = caml_alloc(2, 0);    /* int * int32 */

  int rc = HYPERVISOR_domctl((unsigned long) &op);
  if (rc < 0) {
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, caml_copy_int32(-1));
  } else {
    Store_field(result, 0, Val_int(0));
    Store_field(result, 1, caml_copy_int32(op.u.getdomaininfo.ssidref));
  }

  CAMLreturn(result);
}

CAMLprim value
caml_flask_getpeersid(value evt)
{
  CAMLparam1(evt);

  xen_flask_op_t flask_op;
  flask_op.cmd = FLASK_GET_PEER_SID;
  flask_op.interface_version = XEN_FLASK_INTERFACE_VERSION;
  flask_op.u.peersid.evtchn = Int_val(evt);

  CAMLlocal1(result);
  result = caml_alloc(2, 0);    /* int * int32 */

  int rc = HYPERVISOR_xsm_op(&flask_op);
  if (rc < 0) {
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, caml_copy_int32(-1));
  } else {
    Store_field(result, 0, Val_int(0));
    Store_field(result, 1, caml_copy_int32(flask_op.u.peersid.sid));
  }

  CAMLreturn(result);
}

CAMLprim value
caml_flask_create(value ssid, value tsid, value tclass)
{
  CAMLparam3(ssid, tsid, tclass);

  xen_flask_op_t flask_op;
  flask_op.cmd = FLASK_CREATE;
  flask_op.interface_version = XEN_FLASK_INTERFACE_VERSION;
  flask_op.u.transition.ssid = Int32_val(ssid);
  flask_op.u.transition.tsid = Int32_val(tsid);
  flask_op.u.transition.tclass = Int32_val(tclass);

  CAMLlocal1(result);
  result = caml_alloc(2, 0);      /* int * int32 */

  int rc = HYPERVISOR_xsm_op(&flask_op);
  if (rc < 0) {
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, caml_copy_int32(-1));
  } else {
    Store_field(result, 0, Val_int(0));
    Store_field(result, 1, caml_copy_int32(flask_op.u.transition.newsid));
  }

  CAMLreturn(result);
}

CAMLprim value
caml_flask_access(value request)
{
  CAMLparam1(request);

  uint32_t c_ssid   = Int32_val(Field(request, 0));
  uint32_t c_tsid   = Int32_val(Field(request, 1));
  uint32_t c_tclass = Int32_val(Field(request, 2));
  uint32_t c_req    = Int32_val(Field(request, 3));

  xen_flask_op_t flask_op;

  flask_op.cmd               = FLASK_ACCESS;
  flask_op.interface_version = XEN_FLASK_INTERFACE_VERSION;
  flask_op.u.access.ssid     = c_ssid;
  flask_op.u.access.tsid     = c_tsid;
  flask_op.u.access.tclass   = c_tclass;
  flask_op.u.access.req      = c_req;

  CAMLlocal2(result, avd);
  result = caml_alloc(2, 0);      /* int * av_decision */
  avd    = caml_alloc(4, 0);      /* av_decision */

  int rc = HYPERVISOR_xsm_op(&flask_op);
  if (rc < 0) {
    Store_field(avd, 0, Val_bool(0));
    Store_field(avd, 1, caml_copy_int32(0));
    Store_field(avd, 2, caml_copy_int32(0));
    Store_field(avd, 3, caml_copy_int32(0xFFFFFFFF));
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, avd);
  } else {
    Store_field(avd, 0, Val_bool(1));
    Store_field(avd, 1, caml_copy_int32(flask_op.u.access.allowed));
    Store_field(avd, 2, caml_copy_int32(flask_op.u.access.audit_allow));
    Store_field(avd, 3, caml_copy_int32(flask_op.u.access.audit_deny));
    Store_field(result, 0, Val_int(0));
    Store_field(result, 1, avd);
  }

  CAMLreturn(result);
}
