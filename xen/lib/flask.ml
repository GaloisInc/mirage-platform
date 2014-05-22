(*
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
 *)

open Printf

(* Type Definitions *)

type sid = int32
type context = string
type oclass = int32
type av = int32

type av_request = {
  ssid : sid;
  tsid : sid;
  tclass : oclass;
  req : av;
}

type av_decision = {
  result : bool;
  allowed : av;
  audit_allow : av;
  audit_deny : av;
}

(* C stubs defined in "flask_stubs.c".  These functions return a
 * tuple of (error_code * return_value).  The 'error_code' is zero on
 * success, or a Xen error value on failure. *)
module Raw = struct
  external context_to_sid : string -> (int * int32)
    = "caml_flask_context_to_sid"

  external sid_to_context : int32 -> (int * string)
    = "caml_flask_sid_to_context"

  external access : av_request -> (int * av_decision)
    = "caml_flask_access"

  external getdomainsid : int -> (int * int32)
    = "caml_flask_getdomainsid"

  external getpeersid : int -> (int * int32)
    = "caml_flask_getpeersid"

  external create : int32 -> int32 -> int32 -> (int * int32)
    = "caml_flask_create"
end

let check_error code =
  match code with
  | 0 -> ()
  | x -> failwith (sprintf "flask error: %d" x)

(* Security IDs and Contexts *)

let sid_to_string = Int32.to_string

let context_to_sid ctx =
  let (err, sid) = Raw.context_to_sid ctx in
  check_error err;
  sid

let sid_to_context sid =
  let (err, ctx) = Raw.sid_to_context sid in
  check_error err;
  ctx

(* Object Classes *)

let oclass_of_int32 x = x
let oclass_to_string = Int32.to_string

(* Access Vectors *)

let av_of_int32 x = x
let av_of_list = List.fold_left Int32.logor 0l
let av_to_string = sprintf "0x%lx"

(* Access Checks *)

let access avreq =
  let (err, avd) = Raw.access avreq in
  check_error err;
  avd

(* Other Calls *)

let getdomainsid domid =
  let (err, sid) = Raw.getdomainsid domid in
  check_error err;
  sid

let getpeersid evt =
  let (err, sid) = Raw.getpeersid (Eventchn.to_int evt) in
  check_error err;
  sid

let create ssid tsid tclass =
  let (err, sid) = Raw.create ssid tsid tclass in
  check_error err;
  sid
