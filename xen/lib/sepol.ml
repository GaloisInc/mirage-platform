(*
 * sepol.ml --- libsepol security hooks.
 *
 * Copyright (C) 2013, Galois, Inc.
 * All Rights Reserved.
 *
 * Written by James Bielman <jamesjb@galois.com>, 18 December 2013
 *)

open Int32
open Printf
(* open Flask_gen *)

(* An access decision returned by "compute_av". *)
type av_decision = {
  allowed : int32;
  decided : int32;
  auditallow : int32;
  auditdeny : int32
}

(* Bindings to libsepol stubs defined in "sepol_stubs.c". *)
module Raw = struct
  external load_policy : Io_page.t -> unit = "load_policy"
  external compute_av : int32 -> int32 -> int32 -> int32 -> (int * av_decision) = "compute_av"
  external transition_sid : int32 -> int32 -> int32 -> (int * int32) = "transition_sid"
  external check_context : string -> int = "check_context"
  external sid_to_context : int32 -> (int * string) = "sid_to_context"
  external context_to_sid : string -> (int * int32) = "context_to_sid"
end

(* Raise an exception if "code" is negative. *)
let check_error code =
  match code with
  | 0 -> ()
  | x -> failwith (sprintf "sepol error: %d" x)

(* Raise an exception if "rc" is negative, else return "x". *)
let check_error_fst (rc, x) =
  check_error rc;
  x

(* Load a policy from an I/O page. *)
let load_policy = Raw.load_policy

(* Look up a security ID and return its context. *)
let sid_to_context sid =
  check_error_fst (Raw.sid_to_context sid)

(* Look up a context and return its security ID. *)
let context_to_sid context =
  check_error_fst (Raw.context_to_sid context)

(* Compute an access decision for a pair of SIDs, class, and access vector. *)
let compute_av ssid tsid tclass av =
  check_error_fst (Raw.compute_av ssid tsid tclass av)

(* Compute an object creation decision for a pair of SIDs and class. *)
let transition_sid ssid tsid tclass =
  check_error_fst (Raw.transition_sid ssid tsid tclass)

(*
(* Test object creation from the Xenstore policy. *)
let test_transition () =
  let xs_root = InitialSID.xenstore in
  let xs_local_path = context_to_sid "system_u:object_r:xs_local_domain_path_t" in
  let xs_local = transition_sid xs_root xs_local_path Class.xenstore in
  printf "create(%s, %s) -> %s\n%!"
         (sid_to_context xs_root)
         (sid_to_context xs_local_path)
         (sid_to_context xs_local)

(* Test access decision from the Xenstore policy. *)
let test_compute_av () =
  let xs_root  = InitialSID.xenstore in
  let xs_local = context_to_sid "system_u:object_r:xs_local_domain_t" in
  let avd      = compute_av xs_root xs_local Class.xenstore Perm.xenstore__bind in
  printf "allowed=0x%08lx decided=0x%08lx\n%!" avd.allowed avd.decided
*)

(* Main program. *)
(*
let _ =
  load_policy "xenstore.24";
  test_transition ();
  test_compute_av ()
*)

