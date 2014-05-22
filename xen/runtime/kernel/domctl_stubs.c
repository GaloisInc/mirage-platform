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
 * Written by Patrick Colp <pjcolp@galois.com>
 */

#define __XEN_TOOLS__

#include <mini-os/x86/os.h>
#include <mini-os/hypervisor.h>
#include <xen/domctl.h>
#include <xen/xsm/flask_op.h>

#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/bigarray.h>
#include <caml/alloc.h>
#include <caml/fail.h>

CAMLprim value
caml_domctl_getdomaininfo(value domid)
{
  CAMLparam1(domid);

  xen_domctl_t op;
  op.cmd = XEN_DOMCTL_getdomaininfo;
  op.interface_version = XEN_DOMCTL_INTERFACE_VERSION;
  op.domain = Int_val(domid);

  CAMLlocal1(result);
  result = caml_alloc_tuple(3);

  int rc = HYPERVISOR_domctl((unsigned long) &op);
  if (rc < 0) {
    Store_field(result, 0, Val_int(rc));
    Store_field(result, 1, Val_bool(0));
    Store_field(result, 2, Val_bool(0));
  } else {
    Store_field(result, 0, Val_int(op.u.getdomaininfo.domain));
    Store_field(result, 1, Val_bool(op.u.getdomaininfo.flags & XEN_DOMINF_dying));
    Store_field(result, 2, Val_bool(op.u.getdomaininfo.flags & XEN_DOMINF_shutdown));
  }

  CAMLreturn(result);
}

