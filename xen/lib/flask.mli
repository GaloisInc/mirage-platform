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

(*
 * Open Questions:
 *
 * - How should this module react when it is used on a hypervisor
 *   without XSM support?
 *
 * - What if there is XSM support but Flask is not the XSM module?
 *
 * - Improving error handling.  We should, at least, raise specific
 *   exceptions instead of 'Failure'.
 *)

(* Note: The set of object classes and access vectors in use is not
 * defined by this module.  The user will either define them by hand
 * or (more likely) generate them from the XSM policy like the C headers
 * and create them using the '_of_int32' functions defined here.
 *
 * The caller is also responsible for converting classes and avs to
 * strings for its own auditing. *)

(** {2 Security IDs and Contexts} *)

type sid = int32
(** A security identifier. *)

val sid_to_string : sid -> string
(** Convert a sid to a string for printing. *)

type context = string
(** A security context string. *)

val context_to_sid : context -> sid
(** Look up a context and return the sid.  Raises 'Failure'
    if the context does not exist. *)

val sid_to_context : sid -> context
(** Look up a sid and return the context.  Raises 'Failure'
    if the context does not exist. *)

(** {2 Object Classes} *)

type oclass = int32
(** A class of object in the security server. *)

val oclass_of_int32 : int32 -> oclass
(** Initialize an 'oclass' from an 'int32'. *)

val oclass_to_string : oclass -> string
(** Convert an object class to a string for printing. *)

(** {2 Access Vectors} *)

type av = int32
(** A set of permissions being requested or responded. *)

val av_of_int32 : int32 -> av
(** Initialize an 'av' from an 'int32'. *)

val av_of_list : av list -> av
(** Combine a list of access vectors into a single 'av'. *)

val av_to_string : av -> string
(** Convert an 'av' to a string for printing. *)

(** {2 Access Checks} *)

type av_request = {
  ssid : sid;         (* source sid *)
  tsid : sid;         (* target sid *)
  tclass : oclass;    (* target object class *)
  req : av;           (* requested access vector *)
}
(** An access request. *)

type av_decision = {
  result : bool;      (* true if granted *)
  allowed : av;       (* allowed av *)
  audit_allow : av;   (* audit these allowed avs *)
  audit_deny : av;    (* audit these denied avs *)
}
(** An access decision. *)

val access : av_request -> av_decision
(** Perform an access check and return a decision.
  * Raises 'Failure' if any other error occurs. *)

(** {2 Other Calls} *)

val getdomainsid : int -> sid
(** Get the SID for a domain by ID.

    Raises 'Failure' if an error occurs. *)

val getpeersid : Eventchn.t -> sid
(** Get the SID of the peer for an event channel.

    Raises 'Failure' if an error occurs. *)

val create : sid -> sid -> oclass -> sid
(** Perform an object creation transition decision. *)

(* TODO: xen_flask_boolean *)
