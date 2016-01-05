(** The “pure” common library (mostly data) *)
module Host : sig
(**************************************************************************)
(*    Copyright 2014, 2015:                                               *)
(*          Sebastien Mondet <seb@mondet.org>,                            *)
(*          Leonid Rozenberg <leonidr@gmail.com>,                         *)
(*          Arun Ahuja <aahuja11@gmail.com>,                              *)
(*          Jeff Hammerbacher <jeff.hammerbacher@gmail.com>               *)
(*                                                                        *)
(*  Licensed under the Apache License, Version 2.0 (the "License");       *)
(*  you may not use this file except in compliance with the License.      *)
(*  You may obtain a copy of the License at                               *)
(*                                                                        *)
(*      http://www.apache.org/licenses/LICENSE-2.0                        *)
(*                                                                        *)
(*  Unless required by applicable law or agreed to in writing, software   *)
(*  distributed under the License is distributed on an "AS IS" BASIS,     *)
(*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or       *)
(*  implied.  See the License for the specific language governing         *)
(*  permissions and limitations under the License.                        *)
(**************************************************************************)

(** Definition of a host; a place to run commands or handle files. *)
open Internal_pervasives

(** Definitions specific to “SSH” hosts (see {!connection}). *)
module Ssh : sig

  type t = {
    address: string;
    port: int option;
    user: string option;
    add_ssh_options: string list;
  } [@@deriving yojson]
  (** The type of SSH-based hosts. *)

  val configure_ssh_batch_option :
    [ `Custom of string | `Dropbear | `Openssh ] -> unit
    (** Configure global “Batch option”,
      (call [ssh] without password/question):
      {ul
        {li for OpenSSH, it is ["-oBatchMode=yes"],}
        {li for DropBear, it is ["-s"].  }
      }*)

  val ssh_batch_option: t -> string
  (** Get the right option for the SSH client, for now this does not
      actually depend on the Host. *)

end


type default_shell [@@deriving yojson]
(** Specification of the default shell of a Host. *)


type t [@@deriving yojson]
(** Host container.

  A host is the current machine, or an SSH-accessed distant host.
  It may have a plaground: a directory where Ketrew can create runtime-files.
  It keeps track of a default-shell to use (the “default” [default_shell], is
  [("sh", "-c")]).
    
*)

val default_shell :
  ?binary:string ->
  ?options:string list ->
  ?command_option:string ->
  string ->
  default_shell
(** Use
  [default_shell ~binary:"/bin/sh" ~options:["-l"; "--something"; "blah" ]
      ~command_option:"-c" "sh"]
  to define a default-shell calling ["sh -l --something blah -c <command>"].
*)

val localhost:
  ?execution_timeout:Time.t ->
  ?default_shell:default_shell ->
  ?playground:Path.t ->
  ?name:string -> unit -> t
(** The host ["localhost"] (i.e. not over SSH).  *)

val tmp_on_localhost: t
(** The host ["localhost"], with ["/tmp"] as [playground]. *)

val ssh :
  ?execution_timeout:Time.t ->
  ?add_ssh_options:string list ->
  ?default_shell:default_shell ->
  ?playground:Path.t ->
  ?port:int -> ?user:string -> ?name:string -> string -> t
(** Create an SSH host. *)

val named :
  ?execution_timeout:Time.t ->
  ?default_shell:default_shell ->
  ?playground:Path.t ->
  string -> t
(** Create an "named" host, the actual connection will be resolved
    form the name by the engine. *)

val with_ssh_connection: t -> Ssh.t -> t

val shell_of_default_shell: t -> string -> string list

val of_uri :
  Uri.t ->
  (t, [> `Host_uri_parsing_error of string * string ]) Pvem.Result.t
(** Get a [Host.t] from an URI (library {{:https://github.com/mirage/ocaml-uri}ocaml-uri});
    the “path” part of the URI is the playground.

    Optional arguments can be added to the URL:

    - a ["shell"] argument defines the [default_shell].
    - a list of ["ssh-option"] parameters can be added for SSH-based host, they
    add options to SSH/SCP calls.
    - a ["timeout"] value can be defined (in seconds) for all system/SSH calls.

    For example
    [of_string "ssh://user@SomeHost:42/tmp/pg?shell=bash,-l,--init-file,bouh,-c&timeout=42"]
    will be like using 
    {[
      ssh ~default_shell:(default_shell  "bash"
                            ~command_name ~options:["-l"; "--init-file"; "bouh"]
                            ~command_option:"-c")
        ~execution_timeout:42.
        ~port:42 ~user:"user" "SomeHost"]}

*)

val of_string: string ->
  (t, [> `Host_uri_parsing_error of string * string ]) Pvem.Result.t
(** Parse an {{:http://www.ietf.org/rfc/rfc3986.txt}RFC-3986}-compliant
    string into a host, see {!of_uri}. *)

val to_uri: t -> Uri.t
(** Convert a [Host.t] to an URI representing it. *)

val to_string_hum : t -> string
(** Get a display-friendly string for the host. *)

val log : t -> Log.t
(** Get a {!Log.t} document. *)

val markup: t -> Display_markup.t
(** Get a higher-level display document. *)

val execution_timeout: t -> Time.t option
(** The execution timeout configured for the host. *)

val connection: t -> [ `Localhost | `Ssh of Ssh.t | `Named of string ]
val playground: t -> Path.t option
end
module Monitored_script : sig
(**************************************************************************)
(*    Copyright 2014, 2015:                                               *)
(*          Sebastien Mondet <seb@mondet.org>,                            *)
(*          Leonid Rozenberg <leonidr@gmail.com>,                         *)
(*          Arun Ahuja <aahuja11@gmail.com>,                              *)
(*          Jeff Hammerbacher <jeff.hammerbacher@gmail.com>               *)
(*                                                                        *)
(*  Licensed under the Apache License, Version 2.0 (the "License");       *)
(*  you may not use this file except in compliance with the License.      *)
(*  You may obtain a copy of the License at                               *)
(*                                                                        *)
(*      http://www.apache.org/licenses/LICENSE-2.0                        *)
(*                                                                        *)
(*  Unless required by applicable law or agreed to in writing, software   *)
(*  distributed under the License is distributed on an "AS IS" BASIS,     *)
(*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or       *)
(*  implied.  See the License for the specific language governing         *)
(*  permissions and limitations under the License.                        *)
(**************************************************************************)

(** Generate Shell scripts that “monitor” commands. *)

(** The goal of this module is to create shell scripts from a high-level
    representation. The scripts are “monitored” in the sense that code is
    added to log every returned value or failure in a parsable [log] file.
*)

open Internal_pervasives

type t =
  {playground: Path.t; program: Program.t}
  [@@deriving yojson]
(** The definition of a monitored script. *)

val create:  playground:Path.t -> Program.t -> t
(** Create a new script, which will run the list of commands, and store state
    values in the [playground] directory. *)

val log_file : t -> Path.t
(** Path to the log file of the script. *)

val pid_file : t -> Path.t
(** Path to the “PID” file: where the script stores the PID of the process
    running the script, [- pid] will be the process id of the process group
    created by `setsid` (useful for killing the whole process tree). *)

val to_string : ?write_pid:bool -> t -> string
(** Render the [monitored_script] to a shell-script string;
    if [write_pid] is [true] (the default), the script writes the pid to
    [pid_file t]. *)

val parse_log : string ->
  [ `After of string * string * string
  | `Before of string * string * string
  | `Error of string list
  | `Failure of string * string * string
  | `Start of string
  | `Success of string ] list
(** Parse the log file of a [monitored_script]. *)
end
module Path : sig
(**************************************************************************)
(*    Copyright 2014, 2015:                                               *)
(*          Sebastien Mondet <seb@mondet.org>,                            *)
(*          Leonid Rozenberg <leonidr@gmail.com>,                         *)
(*          Arun Ahuja <aahuja11@gmail.com>,                              *)
(*          Jeff Hammerbacher <jeff.hammerbacher@gmail.com>               *)
(*                                                                        *)
(*  Licensed under the Apache License, Version 2.0 (the "License");       *)
(*  you may not use this file except in compliance with the License.      *)
(*  You may obtain a copy of the License at                               *)
(*                                                                        *)
(*      http://www.apache.org/licenses/LICENSE-2.0                        *)
(*                                                                        *)
(*  Unless required by applicable law or agreed to in writing, software   *)
(*  distributed under the License is distributed on an "AS IS" BASIS,     *)
(*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or       *)
(*  implied.  See the License for the specific language governing         *)
(*  permissions and limitations under the License.                        *)
(**************************************************************************)

(** File-path handling *)

type t
  [@@deriving yojson]
(** General type of file-paths.  *)

val file : string -> t
(** Create a path to a file. *)

val directory : string -> t
(** Create a path to a directory. *)

val root: t
(** The root directory (i.e. ["/"] on Unix). *)

val absolute_file_exn : string -> t
(** Create an absolute path to a file, raises [Invalid_argument _] if the path
    is not absolute. *)

val absolute_directory_exn : string -> t
(** Create an absolute path to a directory, raises [Invalid_argument _] if the
    path is not absolute. *)

val relative_directory_exn : string -> t
(** Create a relative  path to a directory, raises [Invalid_argument _] if the
    path is not relative. *)

val relative_file_exn : string -> t
(** Create a relative to a file, raises [Invalid_argument _] if the path
    is not relative. *)

val concat : t -> t -> t
(** Safely concatenate two paths (calls [Filename.concat]). *)

val to_string : t -> string
(** Convert the path to a “Unix” path. *)

val to_string_quoted : t -> string
(** Convert the path to a “Unix” path quoted for a shell command (c.f. [Filename.quoted]). *)

val exists_shell_condition: t -> string
(** Create a ["/bin/sh"] command that checks if the file or directory exists. *)

val size_shell_command: t -> string
(** Create a ["/bin/sh"] command that outputs ["0"] for directories and
    their size for files. *)
end
module Program : sig
(**************************************************************************)
(*    Copyright 2014, 2015:                                               *)
(*          Sebastien Mondet <seb@mondet.org>,                            *)
(*          Leonid Rozenberg <leonidr@gmail.com>,                         *)
(*          Arun Ahuja <aahuja11@gmail.com>,                              *)
(*          Jeff Hammerbacher <jeff.hammerbacher@gmail.com>               *)
(*                                                                        *)
(*  Licensed under the Apache License, Version 2.0 (the "License");       *)
(*  you may not use this file except in compliance with the License.      *)
(*  You may obtain a copy of the License at                               *)
(*                                                                        *)
(*      http://www.apache.org/licenses/LICENSE-2.0                        *)
(*                                                                        *)
(*  Unless required by applicable law or agreed to in writing, software   *)
(*  distributed under the License is distributed on an "AS IS" BASIS,     *)
(*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or       *)
(*  implied.  See the License for the specific language governing         *)
(*  permissions and limitations under the License.                        *)
(**************************************************************************)

(** The “things” to run on a given host. *)

open Internal_pervasives


type t = [
  | `And of t list
  | `Exec of string list
  | `Shell_command of string
] [@@deriving yojson]
(** A program. *)

val to_shell_commands: t -> string list
(** Convert a program to a list of shell commands. *)

val to_single_shell_command: t -> string
(** Convert a program to a shell command. *)

val log: t -> Log.t
(** Create a {!Log.t} document to display a program. *)

val to_string_hum: t -> string
(** Get a display-friendly string of a program. *)

val markup: ?flatten: bool -> t -> Display_markup.t
end
module Protocol : sig
(**************************************************************************)
(*    Copyright 2014, 2015:                                               *)
(*          Sebastien Mondet <seb@mondet.org>,                            *)
(*          Leonid Rozenberg <leonidr@gmail.com>,                         *)
(*          Arun Ahuja <aahuja11@gmail.com>,                              *)
(*          Jeff Hammerbacher <jeff.hammerbacher@gmail.com>               *)
(*                                                                        *)
(*  Licensed under the Apache License, Version 2.0 (the "License");       *)
(*  you may not use this file except in compliance with the License.      *)
(*  You may obtain a copy of the License at                               *)
(*                                                                        *)
(*      http://www.apache.org/licenses/LICENSE-2.0                        *)
(*                                                                        *)
(*  Unless required by applicable law or agreed to in writing, software   *)
(*  distributed under the License is distributed on an "AS IS" BASIS,     *)
(*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or       *)
(*  implied.  See the License for the specific language governing         *)
(*  permissions and limitations under the License.                        *)
(**************************************************************************)

open Internal_pervasives
module Server_status : sig
  type t = {
    time: float;
    read_only: bool;
    tls: [`OpenSSL | `Native | `None ];
    preemptive_bounds: int * int;
    preemptive_queue: int;
    libev: bool;
    database: string;
    host_timeout_upper_bound: float option;
    maximum_successive_attempts: int;
    concurrent_automaton_steps: int;
    gc_minor_words : float;
    gc_promoted_words : float;
    gc_major_words : float;
    gc_minor_collections : int;
    gc_major_collections : int;
    gc_heap_words : int;
    gc_heap_chunks : int;
    gc_compactions : int;
    gc_top_heap_words : int;
    gc_stack_size : int;
    enable_ssh_ui: bool;
  }
  val create:
    database: string ->
    host_timeout_upper_bound: float option ->
    maximum_successive_attempts: int ->
    concurrent_automaton_steps: int ->
    enable_ssh_ui: bool ->
    time:float -> read_only:bool ->
    tls:[ `Native | `OpenSSL | `None ] ->
    preemptive_bounds:int * int ->
    preemptive_queue:int -> libev:bool -> gc:Gc.stat -> t
end

module Process_sub_protocol : sig

  module Command : sig
    type t = {
      connection: string;
      id: string;
      command: string;
    }
  end
  type up = [
    | `Start_ssh_connetion of [
        | `New of string * string (* name × connection-uri *)
        | `Configured of string (* id *)
      ]
    | `Get_all_ssh_ids of string (* client-id *)
    | `Get_logs of string * [ `Full ] (* id *)
    | `Send_ssh_input of string * string (* id × input-string *)
    | `Send_command of Command.t
    | `Kill of string (* id *)
  ]
  module Ssh_connection : sig
    type status = [
      | `Alive of [ `Askpass_waiting_for_input of (float * string) list | `Idle ]
      | `Dead of string
      | `Configured
      | `Unknown of string
    ]
    type t = {
      id: string;
      name: string;
      uri: string;
      status: status;
    }
  end
  module Command_output: sig
    type t = {
      id: string;
      stdout: string;
      stderr: string;
    }
  end
  type down = [
    | `List_of_ssh_ids of Ssh_connection.t list
    | `Logs of string * string (* id × serialized markup *)
    | `Error of string
    | `Command_output of Command_output.t
    | `Ok
  ]

end

module Down_message : sig

  type t = [
    | `List_of_targets of Target.t list
    | `List_of_target_summaries of (string (* ID *) * Target.Summary.t) list
      (* We provide the IDs back because the target could be a
         pointer, Summary.id can be different. *)
    | `List_of_target_flat_states of (string (* ID *) * Target.State.Flat.t) list
    | `List_of_target_ids of string list
    | `Deferred_list_of_target_ids of string * int (* id × total-length *)
    | `List_of_query_descriptions of (string * string) list
    | `Query_result of string
    | `Query_error of string
    | `Server_status of Server_status.t
    | `Ok
    | `Missing_deferred
    | `Process of Process_sub_protocol.down
  ]
  include Json.Versioned.WITH_VERSIONED_SERIALIZATION with type t := t

end

module Up_message : sig
  type time_constraint = [
    | `All
    | `Not_finished_before of float
    | `Created_after of float
    | `Status_changed_since of float
  ]
  type string_predicate = [`Equals of string | `Matches of string]
  type filter = [
    | `True
    | `False
    | `And of filter list
    | `Or of filter list
    | `Not of filter
    | `Status of [
        | `Simple of Target.State.simple
        | `Really_running
        | `Killable
        | `Dead_because_of_dependencies
        | `Activated_by_user
      ]
    | `Has_tag of string_predicate
    | `Name of string_predicate
    | `Id of string_predicate
  ]
  type target_query = {
    time_constraint : time_constraint;
    filter : filter;
  }
  type query_option = [
    | `Block_if_empty_at_most of float
  ]
  type t = [
    | `Get_targets of string list (* List of Ids, empty means “all” *)
    | `Get_available_queries of string (* Id of the target *)
    | `Get_target_summaries of string list (* List of Ids, empty means “all” *)
    | `Get_target_flat_states of
        [`All | `Since of float] * string list * (query_option list)
    (* List of Ids, empty means “all” *)
    | `Call_query of (string * string) (* target-id × query-name *)
    | `Submit_targets of Target.t list
    | `Kill_targets of string list (* List of Ids *)
    | `Restart_targets of string list (* List of Ids *)
    | `Get_target_ids of target_query * (query_option list)
    | `Get_server_status
    | `Get_deferred of string * int * int (* id × index × length *)
    | `Process of Process_sub_protocol.up
  ]
  include Json.Versioned.WITH_VERSIONED_SERIALIZATION with type t := t

  val target_query_markup: target_query -> Display_markup.t
end
end
module Reactive : sig

(**
Convenient wrapper around [React] and [ReactiveData] modules.
*)

type 'a signal = 'a React.S.t

type 'a signal_list_wrap = 'a ReactiveData.RList.t

module Source: sig
  type 'a t
  val create: ?eq:('a -> 'a -> bool) -> 'a -> 'a t
  val set: 'a t -> 'a -> unit
  val signal: 'a t -> 'a signal
  val value: 'a t -> 'a
  val modify: 'a t -> f:('a -> 'a) -> unit
  val modify_opt: 'a t -> f:('a -> 'a option) -> unit
  val map_signal: 'a t -> f:('a -> 'b) -> 'b signal

end
module Signal: sig
  type 'a t = 'a signal
  val map: 'a t -> f:('a -> 'b) -> 'b t
  val bind: 'a t -> f:('a -> 'b t) -> 'b t
  val constant: 'a -> 'a t
  val value: 'a t -> 'a
  val singleton: 'a t -> 'a signal_list_wrap
  val list: 'a list t -> 'a signal_list_wrap
  val tuple_2: 'a t -> 'b t -> ('a * 'b) t
  val tuple_3: 'a t -> 'b t -> 'c t -> ('a * 'b * 'c) t
end
end
module Target : sig
(**************************************************************************)
(*    Copyright 2014, 2015:                                               *)
(*          Sebastien Mondet <seb@mondet.org>,                            *)
(*          Leonid Rozenberg <leonidr@gmail.com>,                         *)
(*          Arun Ahuja <aahuja11@gmail.com>,                              *)
(*          Jeff Hammerbacher <jeff.hammerbacher@gmail.com>               *)
(*                                                                        *)
(*  Licensed under the Apache License, Version 2.0 (the "License");       *)
(*  you may not use this file except in compliance with the License.      *)
(*  You may obtain a copy of the License at                               *)
(*                                                                        *)
(*      http://www.apache.org/licenses/LICENSE-2.0                        *)
(*                                                                        *)
(*  Unless required by applicable law or agreed to in writing, software   *)
(*  distributed under the License is distributed on an "AS IS" BASIS,     *)
(*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or       *)
(*  implied.  See the License for the specific language governing         *)
(*  permissions and limitations under the License.                        *)
(**************************************************************************)

(** Definition of the basic building bloc of a workflow. *)
open Internal_pervasives

(** Definition of command-lines to run on a given {!Host.t}. *)
module Command : sig

  type t = {
    host: Host.t;
    action: Program.t;
  }
  (** The type of commands. *)

  val shell : ?host:Host.t -> string -> t
  (** Create a “shell” command for a given [Host.t]. *)

  val program: ?host:Host.t -> Program.t -> t
  (** Create a [Command.t] that runs a {!Program.t}. *)

  val get_host : t -> Host.t
  (** Get the host. *)

  val log: t -> Log.t
  (** Get a display document. *)

  val markup: t -> Display_markup.t

  val to_string_hum : t -> string
  (** Get a Human-readable string. *)

end

module Volume : sig
  type structure =
      [ `Directory of string * structure list | `File of string ]
  type t = { host : Host.t; root : Path.t; structure : structure; }

  val create : host:Host.t -> root:Path.t -> structure -> t

  val file : string -> structure
  val dir : string -> structure list -> structure

  val all_paths : t -> Path.t list

  val log_structure : structure -> Log.t

  val log : t -> Log.t
  val markup: t -> Display_markup.t

  val to_string_hum : t -> string
end

module Build_process: sig
  type t = [
    | `No_operation
    | `Long_running of (string * string)
    (** Use a long-running plugin: [(plugin_name, initial_run_parameters)].  *)
  ]
  (** Specification of how to build a target. {ul
      {li  [`No_operation]: do nothing, }
      {li [`Long_running (plugin_name, initial_run_parameters)]:
      Use a long-running plugin. }
      }
  *)

  val nop : t
  (** A build process that does nothing. *)
end

type id = Unique_id.t
(** The identifiers of targets. *)

module Condition : sig
  type t = [
    | `Satisfied
    | `Never
    | `Volume_exists of Volume.t
    | `Volume_size_bigger_than of Volume.t * int
    | `Command_returns of Command.t * int
    | `And of t list
  ]
  (**
    An execution anti-condition; the condition defines when a target is
    ready and therefore should be run if the condition is {emph not} met: {ul
    {li with [`Never] the target always runs (because never “ready”),}
    {li with [`Satisfied] the target never runs (a bit useless),}
    {li with [`Volume_exists v] the target runs if the volume does not exist
    ([make]-like behavior).}
    {li with [`Volume_size_bigger_than (v, sz)] Ketrew will get the total size
    of the volume (in bytes) and check that it is bigger.}
    {li with [`Command_returns (c, v)] Ketrew will run the {!Command.t} and
    check its return value.}
    {li [`And list_of_conditions] is a conjunction of conditions.}
      }
  *)

  val log: t -> Log.t
  val to_string_hum: t -> string
  val markup: t -> Display_markup.t

end

module Equivalence: sig
  type t = [
    | `None
    | `Same_active_condition
  ]
end

module State : sig
  type t

  type simple = [
    | `Activable
    | `In_progress
    | `Successful
    | `Failed
  ] [@@deriving yojson]
  val simplify: t -> simple

  val name: t -> string

  type summary =
    [ `Time of Time.t ] * [ `Log of string option ] * [ `Info of string list ]
  val summary : t -> summary

  val log: ?depth:int ->  t -> Log.t

  (** The date the target's creation. *)
  val passive_time: t -> Time.t

  val finished_time: t -> Time.t option

  module Is : sig
    val building : t -> bool
    val tried_to_start : t -> bool
    val started_running : t -> bool
    val starting : t -> bool
    val still_building : t -> bool
    val still_running : t -> bool
    val ran_successfully : t -> bool
    val successfully_did_nothing : t -> bool
    val active : t -> bool
    val verified_success : t -> bool
    val already_done : t -> bool
    val dependencies_failed : t -> bool
    val failed_running : t -> bool
    val failed_to_kill : t -> bool
    val failed_to_start : t -> bool
    val killing : t -> bool
    val tried_to_kill : t -> bool
    val did_not_ensure_condition : t -> bool
    val killed : t -> bool
    val finished : t -> bool
    val passive : t -> bool
    val killable: t -> bool
    val finished_because_dependencies_died: t -> bool
    val activated_by_user: t -> bool
  end

  (** A module providing functions [t -> int] to provide counts. *)
  module Count : sig
    val consecutive_recent_attempts: t -> int
    (** 
      Count how many times a current non-fatal failure state
      “repeats.” I.e. how many [`Tried_to_...] state form recent
      history of the target. *)
  end

  (** A “flat” representation of the state (the “normal”
      representation can be very deep hierarchy, that clients running on
      weak VMs, like Javascript engines, cannot handle)i. *)
  module Flat : sig

    type state = t
      
    type item = private {
      time: float;
      simple: simple;
      name: string;
      message: string option;
      more_info: string list;
      finished: bool;
      depth: int;
    } [@@deriving yojson]

    val time: item ->  float
    val simple: item ->  simple
    val name: item ->  string
    val message: item ->  string option
    val more_info: item ->  string list
    val finished: item -> bool

    type t = private {
      history: item list;
    } [@@deriving yojson]

    val empty: unit -> t
    val of_state : state -> t

    val history: t -> item list

    (** Get the most recent item. *)
    val latest: t -> item option
      
    (** Filter the history with a date, returning a flat-state
        containing only newer items if any. *)
    val since: t -> float -> t option

    (** Merge two flat states into a sorted new one. *)
    val merge: t -> t -> t
  end
end

type t
  [@@deriving yojson]
(** The thing holding targets. *)

val create :
  ?id:id -> ?name:string ->
  ?metadata:[ `String of string ] ->
  ?depends_on:id list ->
  ?on_failure_activate:id list ->
  ?on_success_activate:id list ->
  ?make:Build_process.t ->
  ?condition:Condition.t ->
  ?equivalence: Equivalence.t ->
  ?tags: string list ->
  unit ->
  t
(** Create a target value (not stored in the DB yet). *)



val id : t -> Unique_id.t
(** Get a target's id. *)

val name : t -> string
(** Get a target's user-defined name. *)

val depends_on: t -> id list
val on_success_activate: t -> id list
val on_failure_activate: t -> id list
val metadata: t -> [`String of string] option
val build_process: t -> Build_process.t
val condition: t -> Condition.t option
val equivalence: t -> Equivalence.t
val additional_log: t -> (Time.t * string) list
val tags: t -> string list
val state: t -> State.t


module Automaton : sig

  (** A {i pure} automaton *)

  type failure_reason
  type progress = [ `Changed_state | `No_change ]
  type 'a transition_callback = ?log:string -> 'a -> t * progress
  type severity = [ `Try_again | `Fatal ]
  (* type 'a io_action = [ `Succeeded of 'a | `Failed of 'a ] *)
  type bookkeeping =
    { plugin_name: string; run_parameters: string}
  type long_running_failure = severity * string * bookkeeping
  type long_running_action =  (bookkeeping, long_running_failure) Pvem.Result.t
  type process_check =
    [ `Successful of bookkeeping | `Still_running of bookkeeping ]
  type process_status_check = (process_check, long_running_failure) Pvem.Result.t
  type condition_evaluation = (bool, severity * string) Pvem.Result.t
  type dependencies_status =
    [ `All_succeeded | `At_least_one_failed of id list | `Still_processing ]
  type transition = [
    | `Do_nothing of unit transition_callback
    | `Activate of id list * unit transition_callback
    | `Check_and_activate_dependencies of dependencies_status transition_callback
    | `Start_running of bookkeeping * long_running_action transition_callback
    | `Eval_condition of Condition.t * condition_evaluation transition_callback
    | `Check_process of bookkeeping * process_status_check transition_callback
    | `Kill of bookkeeping * long_running_action transition_callback
  ]
  val transition: t -> transition
end

val activate_exn :
  ?log:string -> t -> reason:[ `Dependency of id | `User ] -> t
(** Get an activated target out of a “submitted” one,
    raises [Invalid_argument _] if the target is in a wrong state. *)

val kill : ?log:string -> t -> t option
(** Get dead target out of a killable one,
    or [None] if not killable. *)

val reactivate :
  ?with_id:id -> ?with_name:string ->
  ?with_metadata:[`String of string] option  ->
  ?log:string -> t -> t
(** *)

val is_equivalent: t -> t -> bool
(** Tell whether the first on is equivalent to the second one. This not
    a commutative operation: the function does not look at
    the second target's [Equivalence] field. *)

val log : t -> Log.t
(** Get a [Log.t] “document” to display the target. *)

val latest_run_parameters: t -> string option
(** Get the most recent serialized
    [run_parameters] if the target is a “long-running”,
    [None] otherwise. *)


module Stored_target : sig
  type target = t
  type t
  val to_json: t -> Json.t
  (** Serialize a target to [Json.t] intermediate representation. *)

  val serialize : t -> string
  (** Serialize a target (for the database). *)

  val deserialize :
    string ->
    (t, [> `Target of [> `Deserilization of string ] ])
      Result.t
      (** Deserilize a target from a string. *)

  val get_target: t -> [ `Target of target | `Pointer of id ]
  val of_target: target -> t

  val id: t -> id

  val make_pointer: from:target -> pointing_to:target -> t
end


module Summary: sig
  type full_target = t
  type t [@@deriving yojson]
  (** A representation of an immutable subset of a target. *)

  val create : full_target -> t
  (** Create a summary of a target value. *)

  val id : t -> Unique_id.t
  (** Get a target's id. *)

  val name : t -> string
  (** Get a target's user-defined name. *)

  val depends_on: t -> id list
  val on_success_activate: t -> id list
  val on_failure_activate: t -> id list
  val metadata: t -> [`String of string] option
  val build_process: t -> Build_process.t
  val condition: t -> Condition.t option
  val equivalence: t -> Equivalence.t
  val tags: t -> string list
end
end
