(** The library that actually does things in a UNIX environment (contains the engine and the server) *)
module Client : sig
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

(**
   The “client” is the frontend to either a standalone engine or an
   HTTP client talking to a server/engine.
*)

open Ketrew_pure.Internal_pervasives
open Unix_io


(** [Error.t] is the type of the error kinds that this module introduces. *)
module Error : sig

  type t =
    [ `Http of
        [ `Call of [ `GET | `POST ] * Uri.t
        | `Targets
        | `Target_query of Unique_id.t * string
        ] *
        [ `Exn of exn
        | `Json_parsing of string * [ `Exn of exn ]
        | `Unexpected_message of Ketrew_pure.Protocol.Down_message.t
        | `Wrong_json of Yojson.Safe.json
        | `Wrong_response of Cohttp.Response.t * string ]
    | `Server_error_response of
        [ `Call of [ `GET | `POST ] * Uri.t ] * string ]

  val log : t -> Log.t
end

type t
(** The handle of the client. *)

val as_client:
  configuration:Configuration.t ->
  f:(client:t ->
     (unit,
      [> `Database of Trakeva.Error.t
      | `Database_unavailable of bytes
      | `Dyn_plugin of
           [> `Dynlink_error of Dynlink.error | `Findlib of exn ]
      | `Failure of bytes
      | `Missing_data of bytes
      | `Target of [> `Deserilization of bytes ]
      | `Wrong_configuration of
           [> `Found of bytes ] * [> `Exn of exn ] ]
      as 'a)
       Deferred_result.t) ->
  (unit, 'a) Deferred_result.t
(** Run the function [f] with a fresh-client created with the [configuration].

    If the configuration can be for an HTTP client, for a standalone
    engine, or for a server (the client behaves like a local standalone
    engine, using {!Configuration.standalone_of_server}).
*)

val configuration: t -> Configuration.t
(** Retrieve the configuration used to create the client. *)

val get_local_engine: t -> Engine.t option
(** Get the handle to the engine (returns [None] if the client is
    an HTTP one). *)

val all_targets: t -> 
  (Ketrew_pure.Target.t list,
   [> `Client of Error.t
   | `Database of Trakeva.Error.t
   | `IO of
        [> `Read_file_exn of string * exn | `Write_file_exn of string * exn ]
   | `Missing_data of Ketrew_pure.Target.id
   | `System of [> `File_info of string ] * [> `Exn of exn ]
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t
(** Get all the current targets. *)

val get_list_of_target_ids : t ->
  query:Ketrew_pure.Protocol.Up_message.target_query ->
  (Ketrew_pure.Target.id list,
   [> `Client of Error.t
   | `Database of Trakeva.Error.t
   | `Missing_data of string
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t
(** Get a list of target IDs given the [query]. *)

val get_target: t ->
  id:Ketrew_pure.Target.id ->
  (Ketrew_pure.Target.t,
   [> `Client of Error.t
   | `Database of Trakeva.Error.t
   | `Missing_data of string
   | `Target of [> `Deserilization of string ] ])
   Deferred_result.t
(** The latest contents of a given target.  *)

val get_targets: t ->
  id_list:Ketrew_pure.Target.id list ->
  (Ketrew_pure.Target.t list,
   [> `Client of Error.t
   | `Database of Trakeva.Error.t
   | `Missing_data of string
   | `Target of [> `Deserilization of string ] ])
   Deferred_result.t
(** Same as {!get_target} but “in bulk.” *)

val call_query: t -> target:Ketrew_pure.Target.t -> string ->
  (string, Log.t) Deferred_result.t
(** Call a target's plugin query by name.  *)

val kill: t ->
  Ketrew_pure.Target.id list ->
  (unit,
   [> `Client of Error.t
   | `Database of Trakeva.Error.t
   | `Database_unavailable of Ketrew_pure.Target.id
   | `Missing_data of Ketrew_pure.Target.id
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t
(** Kill a set of targets. *)
    
val restart: t ->
  Ketrew_pure.Target.id list ->
  (unit,
   [> `Client of Error.t
   | `Database of Trakeva.Error.t
   | `Database_unavailable of Ketrew_pure.Target.id
   | `Missing_data of Ketrew_pure.Target.id
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t
(** Restart a set of targets. *)

val submit:
  ?override_configuration:Configuration.t ->
  ?add_tags: string list ->
  EDSL.user_target ->
  unit
(** Submit a high-level workflow description to the engine; this
    function calls [Lwt_main.run].

    One can add tags to all the targets in the workflow before
    submitting with the [add_tags] option.
*)
end
module Command_line : sig
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

(** Command line interface to the engine. *)

open Ketrew_pure.Internal_pervasives

open Unix_io

val run_main :
  ?argv:string array ->
  ?override_configuration:Configuration.t ->
  ?additional_commands: ((unit, string) Deferred_result.t Cmdliner.Term.t * Cmdliner.Term.info) list ->
  unit ->
  [ `Never_returns ]
(** The “main” function for the application, it will [exit n] with [n = 0] if
    succeed or [n > 0] if an error occurs.

    - [argv]: one can provide an array of arguments to be used instead of
    {!Sys.argv}.
    - [override_configuration]: providing a custom configuration will prevent
    Ketrew from looking up a configuration file.
    - [additional_commands]: a list of {!Cmdliner} commands to add to the
    interface.

*)


end
module Configuration : sig
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

(** Definition of the configuration (input to state creation; contents of the
    config-file). *)

open Ketrew_pure.Internal_pervasives
open Unix_io


(** {2 Construct Configuration Values} *)

type t
(** The contents of a configuration. *)

type plugin = [ `Compiled of string | `OCamlfind of string ]
(** The 2 kinds of dynamically loaded “plugins” accepted by Ketrew:

    - [`Compiled path]: path to a `.cma` or `.cmxs` compiled file.
    - [`OCamlfind package]: name of a Findlib package.

*)

type explorer_defaults
(** Configuration of the Explorer text-user-interface.  These
    configuration values can be changed at runtime within the explorer;
    but they are not persistent in that case. *)

val default_explorer_defaults : explorer_defaults
(** The default values of the Explorer configuration. *)

val explorer :
  ?request_targets_ids:[ `All | `Younger_than of [ `Days of float ] ] ->
  ?targets_per_page:int ->
  ?targets_to_prefetch:int -> unit -> explorer_defaults
(** Create a configuration of the Explorer:
    
    - [request_targets_ids]: is used to restrict how many targets are
      visible to the Explorer. 
       The default value is [`Younger_than (`Days 1.5)].
    - [targets_per_page]: how many targets to display in a given
      “page” (default [6]).
    - [targets_to_prefetch]: how many additional targets the Explorer
      should prefetch to speed-up navigation (default [6]).

 *)

type ui
(** General configuration of the text-based user interface. *)

val ui:
  ?with_color:bool ->
  ?explorer:explorer_defaults ->
  ?with_cbreak:bool ->
  unit -> ui
(** Create a configuration of the UI:
    
    - [with_color]: ask Ketrew to use ANSI colors (default: [true]).
    - [explorer]: the configuration of The Explorer (cf. {!explorer}).
    - [with_cbreak]: should the UI use “[cbreak]” or not.  When
      [false], it reads from [stdin] classically (i.e. it waits for
      the [return] key to be pressed); when [true], it gets the
      key-presses directly (it's the default but requires a compliant
      terminal).

 *)

type engine
(** The configuration of the engine, the component that orchestrates
    the run of the targets (used both for standalone and server modes). *)

val engine: 
  ?database_parameters:string ->
  ?turn_unix_ssh_failure_into_target_failure: bool ->
  ?host_timeout_upper_bound: float ->
  ?maximum_successive_attempts: int ->
  unit -> engine
(** Build an [engine] configuration:

    - [database_parameters]: the URI passed to the [trakeva_of_uri]
      library to create the database
      (the default is a Sqlite database: ["~/.ketrew/database"]).
    - [turn_unix_ssh_failure_into_target_failure]: when an
      SSH or system call fails it may not mean that the command in
      your workflow is wrong (could be an SSH configuration or
      tunneling problem). By default (i.e. [false]), Ketrew tries to
      be clever and does not make targets fail. To change this
      behavior set the option to [true].
    - [host_timeout_upper_bound]: every connection/command timeout
      will be “≤ upper-bound” (in seconds, default is [60.]).
    - [maximum_successive_attempts]: number of successive non-fatal
      failures allowed before declaring a target dead (default is [10]).
*)

type authorized_tokens 
(** This type is a container for one more authentication-tokens,
    used by the server's HTTP API

    Tokens have a name and a value; the value is the one checked
    against the ["token"] argument of the HTTP queries.
 *)

val authorized_token: name: string -> string -> authorized_tokens
(** Create an “inline” authentication token, i.e. provide a [name] and
    a value directly. *)

val authorized_tokens_path: string -> authorized_tokens
  (** Ask the server to load tokens from a file at the given path.

      The file uses the SSH
      {{:http://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#.7E.2F.ssh.2Fauthorized_keys}[authorized_keys]} format.
      I.e. whitespace-separated lines of the form:
      {v
      <name> <token> <optional comments ...>
      v}
  *)

type server
(** The configuration of the server. *)

val server: 
  ?ui:ui ->
  ?engine:engine ->
  ?authorized_tokens: authorized_tokens list ->
  ?return_error_messages: bool ->
  ?command_pipe: string ->
  ?daemon: bool ->
  ?log_path: string ->
  ?max_blocking_time: float ->
  ?block_step_time: float ->
  ?read_only_mode: bool ->
  [ `Tcp of int | `Tls of string * string * int ] ->
  [> `Server of server]
(** Create a server configuration (to pass as optional argument to the
    {!create} function).

    - [authorized_tokens]: cf. {!authorized_token} and
      {!authorized_tokens_path}.
    - [return_error_messages]: whether the server should return explicit error
      messages to clients (default [false]).
    - [command_pipe]: path to a named-piped for the server to listen to
      commands (this is optional but highly recommended).
    - [daemon]: whether to daemonize the server or not (default
      [false]). If [true], the server will detach from the current
      terminal and change the process directory to ["/"]; hence if you
      use this option it is required to provide absolute paths for all
      other parameters requiring paths.
    - [log_path]: if set together with [daemonize], ask the server to
      redirect logs to this path (if not set, daemon logs go to ["/dev/null"]).
    - [max_blocking_time]: 
      upper bound on the request for blocking in the protocol (seconds,
      default [300.]).
    - [block_step_time]: 
      granularity of the checking for blocking conditions (this will
      hopefully disapear soon) (seconds, default [3.]).
    - [read_only_mode]:
      run the server in read-only mode (default [false]).
    = [`Tcp port]: configure the server the unsercurely listen on [port].
    - [`Tls ("certificate.pem", "privatekey.pem", port)]: configure the OpenSSL
      server to listen on [port].
*)

type standalone
val standalone: ?ui:ui -> ?engine:engine -> unit -> [> `Standalone of standalone]

type client
(** Configuration of the client (as in HTTP client). *)

val client: ?ui:ui -> token:string -> string -> [> `Client of client]
(** Create a client configuration:
    
    - [ui]: the configuration of the user-interface, cf. {!ui}.
    - [token]: the authentication token to use to connect to the
      server (the argument is optional but nothing interesting can
      happen without it).
    - the last argument is the connection URI,
      e.g. ["https://example.com:8443"].

*)

type mode = [
  | `Standalone of standalone
  | `Server of server
  | `Client of client
]
(** Union of the possible configuration “modes.” *)

val create : ?debug_level:int -> ?plugins: plugin list -> mode  -> t
(** Create a complete configuration:

    - [debug_level]: integer specifying the amount of verbosity
      (current useful values: [0] for quiet, [1] for verbose, [2] for
      extremely verbose —- [~debug_level:2] will slow down the engine
      noticeably).
    - [plugins]: cf. {!type:plugin}.
    - [mode]: cf. {!standalone}, {!client}, and {!server}.

 *)

type profile
(** A profile is a name associated with a configuration. *)

val profile: string -> t -> profile
(** Create a profile value. *)

(** {2 Output/Serialize Configuration Profiles} *)

val output: profile list -> unit
(** Output a configuration file containing a list of profiles to [stdout]. *)

val to_json: profile list -> string
(** Create the contents of a configuration file containing a list of
    profiles. *)

(** {2 Access Configuration Values} *)

val default_configuration_directory_path: string
(** Default path to the configuration directory (["~/.ketrew/"]). *)

val database_parameters: engine -> string
(** Get the database parameters. *)

val is_unix_ssh_failure_fatal: engine -> bool
(** Should we kill targets on ssh/unix errors. *)

val maximum_successive_attempts: engine -> int
(** Get the maximum number of successive non-fatal failures. *)
  
val plugins: t ->  plugin list
(** Get the configured list of plugins. *)

val mode: t -> mode

val standalone_engine: standalone -> engine
val server_engine: server -> engine

val server_configuration: t -> server option
(** Get the potentiel server configuration. *)

val authorized_tokens: server ->
  [ `Path of string | `Inline of (string * string)] list
(** The path to the [authorized_tokens] file. *)

val listen_to: server -> [ `Tcp of int | `Tls of string * string * int ]
(** Get the OpenSSL-or-not server configuration. *)

val return_error_messages: server -> bool
(** Get the value of [return_error_messages]. *)

val command_pipe: server -> string option
(** Get the path to the “command” named pipe. *)

val daemon: server -> bool
(** Tell whether the server should detach. *)

val log_path: server -> string option
(** Get the path to the server's log file. *)

val log: t -> Log.t
(** Get a display-friendly list of configuration items. *)

val connection: client -> string
val token: client -> string

val standalone_of_server: server -> standalone

val with_color: t -> bool
val request_targets_ids: t -> [ `All | `Younger_than of [ `Days of float ] ]
val targets_per_page: t -> int
val targets_to_prefetch: t -> int

val max_blocking_time: server -> float
val block_step_time:   server -> float
val read_only_mode:    server -> bool

val use_cbreak: unit -> bool
(** See the documentation of [with_cbreak]. *)

val load_exn:
  ?and_apply:bool ->
  ?profile:string ->
  [ `From_path of string
  | `Guess
  | `In_directory of string
  | `Override of t ] ->
  t
(** Load a configuration.

    If [and_apply] is [true] (the default), then global settings are applied
    and plugins are loaded.

    When the configuration comes from a file, the argument [profile]
    allows to load a given profile. If [None] then the loading process
    will try the ["KETREW_PROFILE"] environment variable, or use the name
    ["default"].
    
    The last argument tells the functions how to load the configuration:
    
    - [`Override c]: use [c] as configuration
    - [`From_path path]: parse the file [path]
    - [`In_directory root]: look for configuration files in the [root]
      directory
    - [`Guess]: use environment variables and/or default values to
      find the configuration file.

   *)


end
module Daemonize : sig
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

(** Implementation of the {!LONG_RUNNING} API with [nohup setsid] unix
    processes or generated Python scripts. *)

(** This module implements the {!Long_running.LONG_RUNNING} plugin-API.

    Shell commands are put in a {!Ketrew_pure.Monitored_script.t}, and
    run in the background (detached in a new process group).

    There are two methods for starting/detaching the computation
    (set with the [~using] parameter): 

    - [`Nohup_setsid] (the default) means that the script will be started with
    ["nohup setsid bash <script> &"].
    This method is the {i POSIX-ly} portable one; but, sadly,
    it is broken on MacOSX
    (c.f. people having
    {{:https://github.com/ChrisJohnsen/tmux-MacOSX-pasteboard}TMux problems}, 
    {{:http://stackoverflow.com/questions/23898623/nohup-cant-detach-from-console}Nohup problems}).

    - [`Python_daemon] means that the script will be started by
    a generated Python script.
    Obviously, this works only when the host can run Python scripts (which
    includes MacOSX).


    The {!update} function uses the log-file of the monitored-script, and the
    command ["ps -p <Group-PID>"].

    The {!kill} function kills the process group (created thanks to ["setsid"])
    with ["kill -- <N>"] (where ["<N>"] is the negative PID of the group).

*)

type run_parameters
  [@@deriving yojson]

(** The “standard” plugin-API. *)
include Long_running.LONG_RUNNING with type run_parameters := run_parameters

val create:
  ?starting_timeout:float ->
  ?call_script:(string -> string list) ->
  ?using:[ `Nohup_setsid | `Python_daemon] ->
  ?host:Ketrew_pure.Host.t -> ?no_log_is_ok: bool -> Ketrew_pure.Program.t ->
  [> `Long_running of string * string ]
(** Create a “long-running” {!Ketrew_pure.Target.build_process} (run parameters
    are already serialized), see {!Edsl.daemonize} for more
    details *)


val markup : run_parameters -> Ketrew_pure.Internal_pervasives.Display_markup.t
end
module Document : sig
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

(** Transform complex Ketrew values into display-friendly {!Log.t} values. *)
val build_process : ?with_details:bool ->
    [< `Long_running of string * string | `No_operation ] ->
    SmartPrint.t

val target_for_menu : Ketrew_pure.Target.t -> Log.t

val metadata: full:bool -> [ `String of string ] -> Log.t

val target : ?build_process_details:bool ->
  ?condition_details:bool ->
  ?metadata_details:bool ->
  Ketrew_pure.Target.t ->
  Log.t
end
module EDSL : sig
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

(** Easy interface to the library {b for end users}. *)
(**

  This is a more stable EDSL/API for end-users to make workflows and deal with
  the system.

  Many functions may raise exceptions when called improperly, but this
  should happen while building the workflow, not after it starts running. *)

open Ketrew_pure

(** {3 Hosts} *)

module Host: sig

  type t = Ketrew_pure.Host.t
  (** Alias for the host type. *)

  val parse : string -> t
  (** Parse an URI string into a host.

      For example:
      ["ssh://user@SomeHost:42/tmp/pg?shell=bash,-l,--init-file,bouh,-c&timeout=42&ssh-option=-K"]

      - ["ssh:"] means to connect with SSH (if a hostname is defined this is the
      default and only way).
      - ["user"] is the user to connect as.
      - ["SomeHost"] is the hostname, if the “host-connection” part of the URI is
      not provided, “localhost” will be assumed (and SSH won't be used).
      - ["42"] is the port.
      - ["/tmp/pg"] is the “playground”; a directory where the Ketrew-engine will
      create temporary and monitoring files.
      - ["shell=bash,-l,--init-file,bouh,-c"] the option [shell] define the
      shell, and the options, to use on the host.
      - ["timeout=42.5"] is the execution timeout, an optional float setting the
      maximal duration Ketrew will wait for SSH commands to return.
      - ["ssh-option=-K"] are options to pass to the SSH client.

      See also {!Host.of_uri}. *)

  val tmp_on_localhost: t

  val ssh: 
    ?add_ssh_options:string list ->
    ?playground:string ->
    ?port:int -> ?user:string -> ?name:string -> string -> t

  val cmdliner_term :
    ?doc:string -> 
    [ `Required of int | `Flag of string list ] ->
    t Cmdliner.Term.t
    (** Cmdliner term which creates a host argument or flag.
        [`Required n] will be an anonymous argument at position [n]; 
        [`Flag ["option-name"; "O"]] will create an optional
        flag ["--option-name"] (aliased to ["-O"]) whose default value is
        the host ["/tmp/"] (i.e. Localhost with ["/tmp"] as “playground”).
    *)
end

(** {3 Build Programs} *)

(** Build “things to run”, i.e. shell scripts on steroids. *)
module Program: sig

  type t = Ketrew_pure.Program.t
  (** Something to run {i is} a {!Program.t}. *)

  val sh: string -> t
  (** Create a program that runs a shell command. *)

  val shf: ('a, unit, string, t) format4 -> 'a
  (** Printf-like function to create shell commands. *)

  val exec: string list -> t
  (** Create a program that run in [Unix.exec] mode (i.e. does not need shell
      escaping). *)

  val (&&): t -> t -> t
  (** [a && b] is a program than runs [a] then [b] iff [a] succeeded. *)

  val chain: t list -> t
  (** Chain a list of programs like with [&&]. *)


end

(** {3 Conditions } *)


module Condition: sig

  type t = Target.Condition.t

  val (&&): t -> t -> t
  val chain_and: t list -> t
  val never : t
  val program: ?returns:int -> ?host:Host.t -> Program.t -> t

end

(** {3 Artifacts} *)

(** Artifacts are things to be built (they may already exist), most often
    file-tree-locations on a given [host] (see also {!Artifact.t}).
*)
class type user_artifact = object

  method path : string
  (** Return the path of the artifact if the artifact is a volume containing
      a single file or directory. *)

  method exists : Target.Condition.t
  (** Get “exists” condition (for the [~done_when] argument of {!target}. *)

  method is_bigger_than: int -> Target.Condition.t
  (** Get the “is bigger than <size>” condition. *)
end

val file: ?host:Host.t -> string -> user_artifact
(** Create a volume containing one file. *)

val unit : user_artifact
(** The artifact that is “never done” (i.e. the target associated will always
    be (re-)run if activated). *)

(** {3 Targets} *)

(** Targets are the nodes in the workflow arborescence (see also
    {!Target.t}). *)
class type user_target =
  object

    method name : string
    (** Get the name of the target *)

    method metadata: [ `String of string ] option
    (** The metadata that has been set for the target ({i work-in-progress}). *)

    method product: user_artifact
    (** The user-artifact produced by the target, if known (raises exception if
        unknown). *)

    (**/**)
    method activate : unit
    (** Activate the target. *)
    method is_active: bool
    method id: Internal_pervasives.Unique_id.t
    method render: Target.t
    method depends_on: user_target list
    method on_failure_activate: user_target list
    method on_success_activate: user_target list
    method add_tags: string list -> unit
    (**/**)
  end

val target :
  ?active:bool ->
  ?depends_on:user_target list ->
  ?make:Target.Build_process.t ->
  ?done_when:Target.Condition.t ->
  ?metadata:[ `String of string ] ->
  ?product:user_artifact ->
  ?equivalence:Target.Equivalence.t ->
  ?on_failure_activate:user_target list ->
  ?on_success_activate:user_target list ->
  ?tags: string list ->
  string -> user_target
(** Construct a new target, the node of a workflow graph. The main
    argument (the [string]) is its name, then all optional arguments mean:

  - [?active]: whether this target should be started by the engine or
    wait to be ativated by another target (through [depends_on] or
    [on_{success,failure}_activate]) (default:
    [false], i.e., inactive). Usual workflows should not set this
    value since the function {!Ketrew.Cliean.submit} will activate the
    toplevel target automatically.
  - [?depends_on]: list of the dependencies of the target.
  - [?make]: the build-process used to “build” the target; where the
    computation happens.
  - [?done_when]: the condition that the target ensures (checked
    before potentially running and after running).
  - [?metadata]: arbitrary metadata to attach to the target.
  - [?product]: the {!user_artifact} that the target embeds (returned
    by the [#product] method of the target).
  - [?equivalence]: how to tell if two targets are equivalent (and
    then will be merged by the engine). The default is
    [`Same_active_condition] which means that if two targets have the
    same non-[None] [?done_when] argument they will be considered
    equivalent (i.e. they try to “ensure the same condition”).
  - [?on_failure_activate]: targets to activate when this target fails.
  - [?on_success_activate]: targets to activate when this target succeeds.
  - [?tags]: arbitrary tags to add to the target (e.g. for
    search/filter in the UI)

*)

val file_target:
  ?depends_on:user_target list ->
  ?make:Target.Build_process.t ->
  ?metadata:[ `String of string ] ->
  ?name:string ->
  ?host:Host.t ->
  ?equivalence:Target.Equivalence.t ->
  ?on_failure_activate:user_target list ->
  ?on_success_activate:user_target list ->
  ?tags: string list ->
  string ->
  user_target
(** Create a file {!user_artifact} and the {!user_target} that produces it.

    The [?product] of the target will be the file given as argument on
    the host given by the [?host] option (default: localhost using ["/tmp"]).
    
    The [?done_when] condition will be the existence of that file.
    
    This can be seen as a classical [make]-like file-producing target,
    but on any arbitrary host.
*)

val daemonize :
  ?starting_timeout:float ->
  ?call_script:(string -> string list) ->
  ?using:[`Nohup_setsid | `Python_daemon] ->
  ?host:Host.t ->
  ?no_log_is_ok: bool ->
  Program.t ->
  Target.Build_process.t
(** Create a “daemonize” build process:

    - [?host]: the [Host.t] on which the program is to be run.
    - [?starting_timeout]: how long to wait before considering that a
      script failed to start (default: [5.] seconds).
    - [?call_script]: function creating a [Unix.exec]-style command
      given a shell script path 
      (default: [(fun script -> ["bash"; script])]).
    - [?using]: which method to use when damonizing on the [host]
    (see {!Ketrew_daemonize} for more details).
    - [?no_log_is_ok]: consider that if the script run does not
      produce a log file, the process still has succeeded (the default
      and most common is [false], this can be useful for example when
      the [Program.t] or [call_script] do something special over the
      network).

*)

val lsf :
  ?host:Host.t ->
  ?queue:string ->
  ?name:string ->
  ?wall_limit:string ->
  ?processors:[ `Min of int | `Min_max of int * int ] ->
  ?project:string ->
  Program.t -> Target.Build_process.t
(** Create an “LSF” build process. *)

val pbs :
  ?host:Host.t ->
  ?queue:string ->
  ?name:string ->
  ?wall_limit:[ `Hours of float ] ->
  ?processors:int ->
  ?email_user:[ `Always of string | `Never ] ->
  ?shell:string ->
  Program.t ->
  [> `Long_running of string * string ]
(** Create a “PSB” build process. *)


val yarn_application :
  ?host:Host.t ->
  ?daemonize_using:[ `Nohup_setsid | `Python_daemon ] ->
  ?daemon_start_timeout:float ->
  Program.t -> [> `Long_running of string * string ]
(** Create a build process that requests resources from Yarn, the
    command must be an application in the Yarn sense (i.e.
    a program that is going to contact Yarn by itself to request
    containers):

    - [?host]: the “login” node of the Yarn cluster (default: localhost).
    - [?daemonize_using]: how to daemonize the process that calls and
      waits-for the application-manager (default: [`Python_daemon]).
    - [?daemon_start_timeout]: the timeout for the daemon.

*)

val yarn_distributed_shell :
  ?host:Host.t ->
  ?daemonize_using:[ `Nohup_setsid | `Python_daemon ] ->
  ?daemon_start_timeout:float ->
  ?hadoop_bin:string ->
  ?distributed_shell_shell_jar:string ->
  container_memory:[ `GB of int | `MB of int | `Raw of string ] ->
  timeout:[ `Raw of string | `Seconds of int ] ->
  application_name:string ->
  Program.t -> [> `Long_running of string * string ]
(** Create a build process that will use Hadoop's `DistributedShell`  class
    to request a container to run the given arbitrary program.

    - [?host]: the “login” node of the Yarn cluster (default: localhost).
    - [?daemonize_using]: how to daemonize the process that calls and
      waits-for the application-manager (default: [`Python_daemon]).
    - [?daemon_start_timeout]: the timeout for the daemon.
    - [hadoop_bin]: the [hdaoop] executable (default: ["hadoop"]).
    - [distributed_shell_shell_jar]:
    path to the Jar file containing the
    [org.apache.hadoop.yarn.applications.distributedshell.Client] class
    (default: ["/opt/cloudera/parcels/CDH/lib/hadoop-yarn/hadoop-yarn-applications-distributedshell.jar"]
    which seems to be the default installation path when using Cloudera-manager).
    - [container_memory]: how much memory to request from Yarn for the container
    ([`GB 42] for 42 GB; [`Raw some_string] to pass directly [some_string]
    to the option ["-container_memory"] of [distributedshell.Cllient]).
    - [timeout]: the “whole application” timeout
    ([`Seconds (24 * 60 * 60)] for about a day, [`Raw some_string] to
    pass directly [some_string] to the option ["-timeout"] of
    [distributedshell.Cllient]).
    - [application_name]: name of the application for Yarn (it is not
      sanitized by Ketrew and, at least with some configurations, Yarn
      can fail if this string contains spaces for example).

*)


(** {2 Utilities } *)

val to_display_string :
  ?ansi_colors:bool ->
  ?indentation:int ->
  user_target ->
  string
(** Build a display-friendly string summarizing the workflow. *)


end
module Engine : sig
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

(** The engine of the actual Workflow Engine. *)

open Ketrew_pure.Internal_pervasives
open Unix_io

type t
(** The contents of the application engine. *)

val with_engine: 
  configuration:Configuration.engine ->
  (engine:t ->
   (unit, [> `Database of Trakeva.Error.t
          | `Failure of string
          | `Missing_data of bytes
          | `Database_unavailable of Ketrew_pure.Target.id
          | `Target of [> `Deserilization of bytes ]
          | `Dyn_plugin of
               [> `Dynlink_error of Dynlink.error | `Findlib of exn ]
          ] as 'merge_error) Deferred_result.t) ->
  (unit, 'merge_error) Deferred_result.t
(** Create a {!engine.t}, run the function passed as argument, and properly dispose of it. *)

val load: 
  configuration:Configuration.engine ->
  (t,
   [> `Database of Trakeva.Error.t
   | `Failure of string
   | `Missing_data of bytes
   | `Target of [> `Deserilization of bytes ]
   | `Dyn_plugin of
        [> `Dynlink_error of Dynlink.error | `Findlib of exn ]
   ]) Deferred_result.t

val unload: t -> 
  (unit, [>
      | `Database_unavailable of Ketrew_pure.Target.id
      | `Database of  Trakeva.Error.t
    ]) Deferred_result.t

val configuration: t -> Configuration.engine
(** Retrieve the configuration. *)

val add_targets :
  t ->
  Ketrew_pure.Target.t list ->
  (unit,
   [> `Database of Trakeva.Error.t
   | `Database_unavailable of Ketrew_pure.Target.id
   | `Missing_data of Ketrew_pure.Target.id
   | `Target of [> `Deserilization of string ]
   ]) Deferred_result.t
(** Add a list of targets to the engine. *)

val get_target: t -> Unique_id.t ->
  (Ketrew_pure.Target.t,
   [> `Database of Trakeva.Error.t
   | `Missing_data of string
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t
(** Get a target from its id. *)

val all_targets :
  t ->
  (Ketrew_pure.Target.t list,
   [> `Database of Trakeva.Error.t
    | `IO of
        [> `Read_file_exn of string * exn | `Write_file_exn of string * exn ]
    | `Missing_data of Ketrew_pure.Target.id
    | `System of [> `File_info of string ] * [> `Exn of exn ]
    | `Target of [> `Deserilization of string ] ])
  Deferred_result.t
(** Get the list of targets currently handled. *)

val get_list_of_target_ids: t ->
  Ketrew_pure.Protocol.Up_message.target_query ->
  (Ketrew_pure.Target.id list,
   [> `Database of Trakeva.Error.t
   | `Missing_data of string
   | `Target of [> `Deserilization of string ] ]) Deferred_result.t
(** Get only the Ids of the targets for a given “query”:
    
- [`All] for all the targets visible to the engine.
- [`Not_finished_before _] for the targets that were not finished at a given date.
*)

module Run_automaton : sig
  val step :
    t ->
    (bool,
     [> `Database of  Trakeva.Error.t
     | `Database_unavailable of Ketrew_pure.Target.id
     | `Missing_data of Ketrew_pure.Target.id
     | `Target of [> `Deserilization of string ] ])
      Deferred_result.t
  (** Run one step of the engine; [step] returns [true] if something happened. *)

  val fix_point: t ->
    ([ `Steps of int],
     [> `Database of Trakeva.Error.t
     | `Database_unavailable of Ketrew_pure.Target.id
     | `Missing_data of Ketrew_pure.Target.id
     | `Target of [> `Deserilization of string ] ])
      Deferred_result.t
      (** Run {!step} many times until nothing happens or nothing “new” happens. *)
end

val get_status : t -> Ketrew_pure.Target.id ->
  (Ketrew_pure.Target.State.t,
   [> `Database of Trakeva.Error.t
   | `IO of
        [> `Read_file_exn of string * exn | `Write_file_exn of string * exn ]
   | `Missing_data of string
   | `System of [> `File_info of string ] * [> `Exn of exn ]
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t
(** Get the state description of a given target (by “id”). *)

val kill :
  t ->
  id:string ->
  (unit,
   [> `Database of
        [> `Act of Trakeva.Action.t | `Load of string ] * string
   | `Database_unavailable of string ])
    Deferred_result.t
(** Kill a target *)

val restart_target: t -> Ketrew_pure.Target.id -> 
  (Ketrew_pure.Target.id, 
   [> `Database of Trakeva.Error.t
   | `Database_unavailable of Ketrew_pure.Target.id
   | `Missing_data of Ketrew_pure.Target.id
   | `Target of [> `Deserilization of string ] ]) Deferred_result.t
(** Make new activated targets out of a given target and its “transitive
    reverse dependencies” *)

end
module Eval_condition : sig
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

(** Evaluation of {!Ketrew_target.Condition.t} values. *)

open Ketrew_pure.Internal_pervasives

open Unix_io

val bool: Ketrew_pure.Target.Condition.t ->
    (bool,
     [> `Host of
          [> `Execution of
               < host : string; message : string;
                 stderr : string option; stdout : string option >
          | `Non_zero of string * int
          | `Ssh_failure of
               [> `Wrong_log of string
               | `Wrong_status of Unix_process.Exit_code.t ] *
               string
          | `System of [> `Sleep of float ] * [> `Exn of exn ]
          | `Timeout of float
          | `Unix_exec of string ]
            Host_io.Error.execution
     | `Volume of [> `No_size of Log.t ] ]) Deferred_result.t




end
module Explorer : sig
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

open Ketrew_pure.Internal_pervasives
open Unix_io

(** The “Target Explorer™“ *)

type t

val create : client:Client.t -> unit -> t

val explore : t ->
  (unit, [> `Client of Client.Error.t 
         | `Database of Trakeva.Error.t
         | `Database_unavailable of string
         | `Failure of string
         | `IO of [> `Read_file_exn of string * exn
                  | `Write_file_exn of string * exn ]
         | `Missing_data of string
         | `System of [> `File_info of string ] * [> `Exn of exn ]
         | `Target of [> `Deserilization of string ] ]) Deferred_result.t
(** [explore ~client exploration_states] runs a read-eval loop to explore and
    interact with targets.*)
end
module Host_io : sig
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
open Ketrew_pure.Internal_pervasives
open Unix_io



(** Helper functions to build SSH commands. *)
module Ssh : sig
  val scp_push: Ketrew_pure.Host.Ssh.t -> src:string list -> dest:string -> string list
  (** Generate an SCP command for the given host with the destination
      directory or file path. *)

  val scp_pull: Ketrew_pure.Host.Ssh.t -> src:string list -> dest:string -> string list
  (** Generate an SCP command for the given host as source. *)

end


module Error: sig

  type 'a execution = 'a constraint 'a = [>
    | `Unix_exec of string
    | `Execution of
        <host : string; stdout: string option; stderr: string option; message: string>
    | `Ssh_failure of
        [> `Wrong_log of string
        | `Wrong_status of Unix_process.Exit_code.t ] * string 
    | `System of [> `Sleep of float ] * [> `Exn of exn ]
    | `Timeout of float
  ]

  type 'a non_zero_execution = 'a constraint 'a = 
    [> `Non_zero of (string * int) ] execution


  type classified = [
    | `Fatal of string
    | `Recoverable of string
  ]
  (** The “imposed” error types for “long-running” plugins.
      A [`Fatal _] error will make the target die with the error,
      whereas if an error is [`Recoverable _] Ketrew will keep trying
      (for example, a networking error which may not happen later).
  *)

  

  val classify :
    [ `Execution of
        < host : string; message : string; stderr : string option;
          stdout : string option >
    | `Non_zero of string * int
    | `System of [ `Sleep of float ] * [ `Exn of exn ]
    | `Timeout of float
    | `Ssh_failure of
        [> `Wrong_log of string
        | `Wrong_status of Unix_process.Exit_code.t ] *
        string
    | `Unix_exec of string ] ->
    [ `Execution | `Ssh | `Unix ]
  (**
     Get a glance at the gravity of the situation: {ul
     {li [`Unix]: a function of the kind {!Unix.exec} failed.}
     {li [`Ssh]: SSH failed to run something but it does not mean that the
     actual command is wrong.}
     {li [`Execution]: SSH/[Unix] succeeded but the command failed.}
     } *)

  val log :
    [< `Unix_exec of string
    | `Non_zero of (string * int)
    | `System of [< `Sleep of float ] * [< `Exn of exn ]
    | `Timeout of float
    | `Execution of
         < host : string; message : string; stderr : string option;
           stdout : string option; .. >
    | `Ssh_failure of
         [< `Wrong_log of string
         | `Wrong_status of Unix_process.Exit_code.t ] * string ] ->
    Log.t

end

type t = Ketrew_pure.Host.t

val default_timeout_upper_bound: float ref
(** Default (upper bound) of the `?timeout` arguments. *)

type timeout = [ 
  | `Host_default
  | `None
  | `Seconds of float
  | `At_most_seconds of float
]
(** Timeout specification for execution functions below.
    
    - [`Host_default] → use the [excution_timeout] value of the host.     
    - [`None] → force no timeout even if the host has a [execution_timeout].
    - [`Seconds f] → use [f] seconds as timeout.
    - [`At_most_seconds f] -> use [f] seconds, unless the host has a smaller
    [execution_timeout] field.

    The default value is [`At_most_seconds !default_timeout_upper_bound].

*)

val execute: ?timeout:timeout -> t -> string list ->
  (<stdout: string; stderr: string; exited: int>,
   [> `Host of _ Error.execution ]) Deferred_result.t
(** Generic execution which tries to behave like [Unix.execv] even
    on top of SSH. *)

type shell = string -> string list
(** A “shell” is a function that takes a command and returns, and
     execv-style string list; the default for each host
     is ["sh"; "-c"; cmd] *)

val shell_sh: sh:string -> shell
(** Call sh-style commands using the command argument (e.g. [shell_sh "/bin/sh"]
   for a known path or command). *)

val get_shell_command_output :
  ?timeout:timeout ->
  ?with_shell:shell ->
  t ->
  string ->
  (string * string, [> `Host of  _ Error.non_zero_execution]) Deferred_result.t
(** Run a shell command on the host, and return its [(stdout, stderr)] pair
    (succeeds {i iff } the exit status is [0]). *)

val get_shell_command_return_value :
  ?timeout:timeout ->
  ?with_shell:shell ->
  t ->
  string ->
  (int, [> `Host of _ Error.execution ]) Deferred_result.t
(** Run a shell command on the host, and return its exit status value. *)

val run_shell_command :
  ?timeout:timeout ->
  ?with_shell:shell ->
  t ->
  string ->
  (unit, [> `Host of  _ Error.non_zero_execution])  Deferred_result.t
(** Run a shell command on the host (succeeds {i iff } the exit status is [0]).
*)

val do_files_exist :
  ?timeout:timeout ->
  ?with_shell:shell ->
  t ->
  Ketrew_pure.Path.t list ->
  (bool, [> `Host of _ Error.execution ])
  Deferred_result.t
(** Check existence of a list of files/directories. *)

val get_fresh_playground :
  t -> Ketrew_pure.Path.t option
(** Get a new subdirectory in the host's playground *)

val ensure_directory :
  ?timeout:timeout ->
  ?with_shell:shell ->
  t ->
  path:Ketrew_pure.Path.t ->
  (unit, [> `Host of _ Error.non_zero_execution ]) Deferred_result.t
(** Make sure the directory [path] exists on the host. *)

val put_file :
  ?timeout:timeout ->
  t ->
  path: Ketrew_pure.Path.t ->
  content:string ->
  (unit,
   [> `Host of _ Error.execution
    | `IO of [> `Write_file_exn of IO.path * exn ] ])
  Deferred_result.t
(** Write a file on the host at [path] containing [contents]. *)

val get_file :
  ?timeout:timeout ->
  t ->
  path:Ketrew_pure.Path.t ->
  (string,
   [> `Cannot_read_file of string * string
    | `Timeout of Time.t ])
  Deferred_result.t
(** Read the file from the host at [path]. *)

val grab_file_or_log:
  ?timeout:timeout ->
  t -> 
  Ketrew_pure.Path.t ->
  (string, Log.t) Deferred_result.t
(** Weakly typed version of {!get_file}, it fails with a {!Log.t}
    (for use in “long-running” plugins).  *)
end
module Interaction : sig
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

(** Keyboard interaction functions (build “menus”, ask questions, etc.) *)


open Ketrew_pure.Internal_pervasives
open Unix_io


val init : unit -> unit
(** Initialize the module. *)

val toggle_verbose : unit -> unit
(** Turn on or off messages about which key is pressed. *)

type +'a menu_item
(** The type of a menu item. *)

val menu_item : ?char:char -> ?log:SmartPrint.t -> 'a -> 'a menu_item
(** Represent a menu item. *)

val menu : ?max_per_page:int ->
           ?always_there:'a menu_item list ->
           sentence:SmartPrint.t ->
           'a menu_item list ->
             ('a, [> `Failure of string ]) t
(** Display a menu given the specified [menu_items] *)

val open_in_dollar_editor : string -> (unit, 'a) Deferred_result.t
(** Open a file in ["$EDITOR"]. *)

val view_in_dollar_editor : ?extension:string -> string ->
  (unit, [> `IO of [> `Write_file_exn of string * exn ] ]) Deferred_result.t
(** View a string in ["$EDITOR"]. *)

val ask_for_edition : ?extension:string -> string ->
  (string,
   [> `IO of
        [> `Read_file_exn of IO.path * exn
        | `Write_file_exn of IO.path * exn ] ])
    Deferred_result.t
(** Edit content in ["$EDITOR"]. *)

val get_key : unit -> (char, [> `Failure of string ]) t
(** Get a key from the terminal input. *)

val build_sublist_of_targets :
  client: Client.t ->
  list_name:string ->
  all_log:SmartPrint.t ->
  go_verb:SmartPrint.t ->
  filter:(Ketrew_pure.Target.t -> bool) ->
    ([> `Cancel | `Go of string list ],
     [> `Client of Client.Error.t
      | `Database of Trakeva.Error.t
      | `Failure of string
      | `IO of [> `Read_file_exn of string * exn | `Write_file_exn of string * exn ]
      | `Missing_data of string
      | `System of [> `File_info of string ] * [> `Exn of exn ]
      | `Target of [> `Deserilization of string ] ]) t
(** Figure out the targets to be displayed. *)

val make_target_menu : targets:Ketrew_pure.Target.t list ->
    ?filter_target:(Ketrew_pure.Target.t -> bool) ->
    unit ->
      ([> `Go of string ] menu_item) list
(** Create a menu with the targets. *)

val run_with_quit_key :
  < start : (unit, [> `Failure of string ] as 'start_error) Deferred_result.t;
    stop : unit > ->
  (unit, 'start_error) Deferred_result.t
(** Start and run an action until it finishes or unitl the key
    ["q"] is pressed. *)

end
module Long_running_utilities : sig
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

open Ketrew_pure.Internal_pervasives
open Unix_io

val fail_fatal : string -> ('b, [> `Fatal of string ]) Deferred_result.t
(** Call {!Deferred_result.fail} with a “fatal error” (Mandatory in the
    Long-running API). *)

val out_file_path : playground:Ketrew_pure.Path.t -> Ketrew_pure.Path.t
(** Standard path for [stdout] files (given a fresh playground). *)

val err_file_path : playground:Ketrew_pure.Path.t -> Ketrew_pure.Path.t
(** Standard path for [stderr] files. *)

val script_path : playground:Ketrew_pure.Path.t -> Ketrew_pure.Path.t
(** Standard path for monitored-script files. *)

val classify_and_transform_errors :
  ('a,
   [< `Fatal of string
   | `Host of
        [ `Execution of
            < host : string; message : string; stderr : string option;
              stdout : string option >
        | `Non_zero of string * int
        | `Ssh_failure of
            [ `Wrong_log of string
            | `Wrong_status of Unix_process.Exit_code.t ] * string
        | `System of [ `Sleep of float ] * [ `Exn of exn ]
        | `Timeout of float
        | `Unix_exec of string ]
   | `IO of
        [< `Exn of exn
        | `File_exists of string
        | `Read_file_exn of string * exn
        | `Write_file_exn of string * exn
        | `Wrong_path of string ]
   | `System of
        [< `Copy of string
        | `File_info of string
        | `File_tree of string
        | `List_directory of string
        | `Make_directory of string
        | `Make_symlink of string * string
        | `Move of string
        | `Remove of string ] *
        [< `Already_exists
        | `Exn of exn
        | `File_exists of string
        | `File_not_found of string
        | `IO of
            [< `Exn of exn
            | `File_exists of string
            | `Read_file_exn of string * exn
            | `Write_file_exn of string * exn
            | `Wrong_path of string ]
        | `Not_a_directory of string
        | `Wrong_access_rights of int
        | `Wrong_file_kind of string * System.file_info
        | `Wrong_path of string ]
   | `Timeout of 'b ]) Result.t ->
  ('a, [ `Fatal of string | `Recoverable of string ]) Deferred_result.t
(** Transform most known errors into long-running plugin API errors; using
    {!Ketrew_pure.Host.Error.classify}.  *)

val fresh_playground_or_fail :
  Ketrew_pure.Host.t -> (Ketrew_pure.Path.t, [> `Fatal of string ]) Deferred_result.t
(** Get a fresh-playground from a [Host.t]. *)

val get_log_of_monitored_script :
  host:Ketrew_pure.Host.t ->
  script:Ketrew_pure.Monitored_script.t ->
  ([ `After of string * string * string
   | `Before of string * string * string
   | `Error of string list
   | `Failure of string * string * string
   | `Start of string
   | `Success of string ] list option,
   [> `Timeout of Time.t ])
  Deferred_result.t
(** Fetch and parse the [log] file of a monitored-script. *)

val get_pid_of_monitored_script :
  host:Ketrew_pure.Host.t ->
  script:Ketrew_pure.Monitored_script.t ->
  (int option, [> `Timeout of Time.t ]) Deferred_result.t
(** Fetch and parse the [pid] file of a monitored-script. *)

val shell_command_output_or_log :
  host:Ketrew_pure.Host.t ->
  string -> (string, Log.t) Deferred_result.t
(** Call {!Host_io.get_shell_command_output} and transform errors
    into a {!Log.t}. *)
end
module Lsf : sig
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

(** Implementation of the {!LONG_RUNNING} API with the LSF batch processing
    scheduler.
*)

(**
    “Long-running” plugin based on the
    {{:http://en.wikipedia.org/wiki/Platform_LSF}LSF} batch scheduler.

    Shell commands are put in a {!Ketrew_pure.Monitored_script.t}, and
    started with ["bsub [OPTIONS] < <script>"] (we gather the job-id while
    submitting).

    The {!update} function uses the log-file of the monitored-script, and the
    command ["bjobs [OPTIONS] <job-ID>"].

    The {!kill} function kills the job with ["bkill <job-ID>"].

*)


include Long_running.LONG_RUNNING
(** The “standard” plugin API. *)

val create :
  ?host:Ketrew_pure.Host.t ->
  ?queue:string ->
  ?name:string ->
  ?wall_limit:string ->
  ?processors:[ `Min of int | `Min_max of int * int ] ->
  ?project:string ->
  Ketrew_pure.Program.t ->
  [> `Long_running of string  * string ]
  (** Create a “long-running” {!Ketrew_pure.Target.build_process} to run a 
    {!Ketrew_pure.Program.t} on a given LSF-enabled host (run parameters
    already serialized): {ul
      {li [?queue] is the name of the LSF queue requested (["-q"] option). }
      {li [?name] is the job name (["-J"] option). }
      {li [?wall_limit] is the job's Wall-time timeout (["-W"] option). }
      {li [?processors] is the “processors” request (["-n"] option). }
      {li [?project] is the job assigned “project” (["-P"] option). }
    }

*)

end
module Pbs : sig
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

(** Implementation of the {!LONG_RUNNING} API with the PBS batch processing
    scheduler.
*)

(**
    “Long-running” plugin based on the
    {{:http://en.wikipedia.org/wiki/Portable_Batch_System}PBS}
    batch scheduler.

    Shell commands are put in a {!Ketrew_pure.Monitored_script.t}, and
    started with ["qsub [OPTIONS] <script>"] (we gather the job-id while
    submitting).

    The {!update} function uses the log-file of the monitored-script, and the
    command ["qstat [OPTIONS] <job-ID>"].

    The {!kill} function kills the job with ["qdel <job-ID>"].

*)


include Long_running.LONG_RUNNING
(** The “standard” plugin API. *)

val create :
  ?host:Ketrew_pure.Host.t ->
  ?queue:string ->
  ?name:string ->
  ?wall_limit:[ `Hours of float ] ->
  ?processors:int ->
  ?email_user:[ `Always of string | `Never ] ->
  ?shell:string ->
  Ketrew_pure.Program.t ->
  [> `Long_running of string * string ]
(** Create a “long-running” {!Ketrew_pure.Target.build_process} to run a 
    {!Ketrew_pure.Program.t} on a given PBS-enabled host (run parameters
    already serialized): {ul
    {li [?queue] is the name of the PBS queue requested (["-q"] option). }
    {li [?name] is the job name (["-N"] option). }
    {li [?wall_limit] is the job's Wall-time timeout (["-l"] option, default: 24 H). }
    {li [?processors] is the “processors” request (["-l"] option). }
    {li [?email_user] tell PBS to send emails to the given address. }
    {li [?shell] sets the shell used for the ["#!"] of the PBS script. }
    }

*)

end
module Persistent_data : sig
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

open Ketrew_pure
open Internal_pervasives
open Unix_io

type t

val create :
  database_parameters:string ->
  (t,
   [> `Database of
        [> `Get of Trakeva.Key_in_collection.t
        | `Get_all of string
        | `Load of string ] *
        string
   | `Missing_data of string
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t

val unload: t ->
  (unit, [> `Database of [> `Close ] * string ]) Deferred_result.t

val get_target:
  t ->
  Target.id ->
  (Ketrew_pure.Target.t,
   [> `Database of
        [> `Get of Trakeva.Key_in_collection.t | `Load of string ] *
        string
   | `Missing_data of string
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t

val all_targets :
  t ->
  (Ketrew_pure.Target.t list,
   [> `Database of
        [> `Get of Trakeva.Key_in_collection.t
        | `Get_all of string
        | `Load of string ] *
        string
   | `Missing_data of string
   | `Target of [> `Deserilization of string ] ])
    Deferred_result.t


val activate_target :
  t ->
  target:Target.t ->
  reason:[ `Dependency of Target.id | `User ] ->
  (unit,
   [> `Database of
        [> `Act of Trakeva.Action.t | `Load of string ] * string
   | `Database_unavailable of string ])
    Deferred_result.t


val fold_active_targets :
  t ->
  init:'a ->
  f:('a ->
     target:Target.t ->
     ('a,
      [> `Database of
           [> `Get of Trakeva.Key_in_collection.t
           | `Iter of string
           | `Load of string ] *
           string
      | `Missing_data of string
      | `Target of [> `Deserilization of string ] ]
      as 'combined_errors)
       Deferred_result.t) ->
  ('a, 'combined_errors) Deferred_result.t

val move_target_to_finished_collection : (* TODO: rename to “declare_finished” or something *)
  t ->
  target:Target.t ->
  (unit,
   [> `Database of
        [> `Act of Trakeva.Action.t | `Load of string ] * string
   | `Database_unavailable of string ])
    Deferred_result.t

val update_target :
  t ->
  Target.t ->
  (unit,
   [> `Database of
        [> `Act of Trakeva.Action.t | `Load of string ] * string
   | `Database_unavailable of string ])
    Deferred_result.t

module Killing_targets: sig

  val proceed_to_mass_killing :
    t ->
    (bool,
     [> `Database of
          [> `Act of Trakeva.Action.t
          | `Get of Trakeva.Key_in_collection.t
          | `Get_all of string
          | `Load of string ] *
          string
     | `Database_unavailable of string
     | `Missing_data of string
     | `Target of [> `Deserilization of string ] ])
      Deferred_result.t
  val add_target_ids_to_kill_list :
    t ->
    string list ->
    (unit,
     [> `Database of
          [> `Act of Trakeva.Action.t | `Load of string ] * string
     | `Database_unavailable of string ])
      Deferred_result.t
end

module Adding_targets: sig
  val register_targets_to_add :
    t ->
    Target.t list ->
    (unit,
     [> `Database of
          [> `Act of Trakeva.Action.t | `Load of string ] * string
     | `Database_unavailable of string ])
      Deferred_result.t
  val check_and_really_add_targets :
    t ->
    (bool,
     [> `Database of
          [> `Act of Trakeva.Action.t
          | `Get of Trakeva.Key_in_collection.t
          | `Get_all of string
          | `Load of string ] *
          string
     | `Database_unavailable of string
     | `Missing_data of string
     | `Target of [> `Deserilization of string ] ])
      Deferred_result.t
end

module Synchronize: sig
  val copy :
    string ->
    string ->
    (unit,
     [> `Database of Trakeva.Error.t
     | `Database_unavailable of bytes
     | `IO of
          [> `Read_file_exn of bytes * exn
          | `Write_file_exn of bytes * exn ]
     | `Missing_data of bytes
     | `Not_a_directory of bytes
     | `System of
          [> `File_info of bytes
          | `List_directory of bytes
          | `Make_directory of bytes ] *
          [> `Exn of exn | `Wrong_access_rights of int ]
     | `Target of [> `Deserilization of bytes ] ])
      Deferred_result.t
end
end
module Plugin : sig
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


open Ketrew_pure.Internal_pervasives
open Unix_io


val default_plugins :
  (string * (module Long_running.LONG_RUNNING)) list
(** The “long-running” plugins loaded by default. *)

val register_long_running_plugin :
  name:string -> (module Long_running.LONG_RUNNING) -> unit
(** Function to be called from dynamically loaded plugins. *)

val long_running_log: string -> string -> (string * Log.t) list
(** [long_running_log ~state plugin_name serialized_run_params]
    calls {!Long_running.LONG_RUNNING.log} with the right plugin. *)

val additional_queries: Ketrew_pure.Target.t -> (string * Log.t) list
(** Get the potential additional queries ([(key, description)] pairs) that can
    be called on the target. *)

val call_query:  target:Ketrew_pure.Target.t -> string ->
  (string, Log.t) Deferred_result.t
(** Call a query on a target. *)

val find_plugin: string -> (module Long_running.LONG_RUNNING) option

val load_plugins :
  [ `Compiled of string | `OCamlfind of string ] list ->
  (unit,
   [> `Dyn_plugin of
        [> `Dynlink_error of Dynlink.error | `Findlib of exn ]
   | `Failure of string ]) Deferred_result.t

val load_plugins_no_lwt_exn :
  [ `Compiled of string | `OCamlfind of string ] list -> unit
(** Dynamically load a list of plugins, this function is not
    cooperative (with Lwt) and may raise [Failure].

    The specification is (structurally) the same type as
    {!Ketrew_pure.Configuration.plugin}.
*)
end
module Server : sig
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


(**
Implementation of the HTTP server.
*)

open Ketrew_pure.Internal_pervasives

open Unix_io


val start: configuration:Configuration.server ->
  (unit,
   [> `Database of Trakeva.Error.t
   | `Dyn_plugin of
        [> `Dynlink_error of Dynlink.error | `Findlib of exn ]
   | `Failure of bytes
   | `IO of [> `Read_file_exn of bytes * exn ]
   | `Missing_data of bytes
   | `Server_status_error of bytes
   | `Start_server_error of bytes
   | `System of
        [> `File_info of bytes
        | `List_directory of bytes
        | `Remove of bytes ] *
        [> `Exn of exn ]
   | `Target of [> `Deserilization of bytes ] ]) Deferred_result.t
(** Start the server according to its configuration.  *)


val status: configuration:Configuration.server ->
  ([ `Not_responding of string
   | `Running
   | `Wrong_response of Cohttp.Response.t ],
   [> `Failure of string | `Server_status_error of string ]) Deferred_result.t
(** Ask for the status of the server running locally by calling
    ["https://127.0.0.1:<port>/hello"]. *)



val stop: configuration:Configuration.server ->
  ([ `Done | `Timeout ],
   [> `IO of [> `Exn of exn | `File_exists of string | `Wrong_path of string ]
   | `Stop_server_error of string
   | `System of [> `File_info of string ] * [> `Exn of exn ] ]) Deferred_result.t
(** Stop the server by calling the commad ["die"] on the configured
    command-pipe, stopping will fail with [`Stop_server_error _] if
    that path is not configured. *)
end
module Unix_process : sig
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

(** Manage calls to Unix processes *)

open Ketrew_pure.Internal_pervasives
open Unix_io

(** Higher-level representation of Unix exit codes. *)
module Exit_code: sig
  type t = [
    | `Exited of int
    | `Signaled of int
    | `Stopped of int
  ]
  val to_string: t -> string
  val to_log: t -> Log.t
end

val exec :
  ?bin:string ->
  string list ->
  (string * string * Exit_code.t,
   [> `Process of
        [> `Exec of string * string list ] * [> `Exn of exn ] ])
    Deferred_result.t
(** Execute a process with a given list of strings as “[argv]”, if you can
    provide the [~bin] argument to specify the actual file to be executed. The
    function returns the tuple [(stdout, stderr, exit_code)]. *)

val succeed :
  ?bin:string ->
  string list ->
  (string * string,
   [> `Process of
        [> `Exec of string * string list ] *
        [> `Exn of exn | `Non_zero of string ] ])
    Deferred_result.t
(** Do like {!exec} but fail if the process does not exit with [0] status. *)

val error_to_string :
  [< `Process of
       [< `Exec of string * string list ] *
       [< `Exn of exn | `Non_zero of string ] ] ->
  string
(** Display-friendly version of the errors of this module. *)
end
module Yarn : sig
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

(** Implementation of the {!LONG_RUNNING} API asking Aapache Yarn
    for resources and using {!Ketrew_daemonize} to “keep” the
    process group together. *)

(** This module implements {!Ketrew_long_running.LONG_RUNNING} plugin-API.
*)


(** The “standard” plugin-API. *)
include Long_running.LONG_RUNNING


type distributed_shell_parameters

val distributed_shell_program :
  ?hadoop_bin:string ->
  ?distributed_shell_shell_jar:string ->
  container_memory:[ `GB of int | `MB of int | `Raw of string ] ->
  timeout:[ `Raw of string | `Seconds of int ] ->
  application_name:string ->
  Ketrew_pure.Program.t ->
  [> `Distributed_shell of distributed_shell_parameters * Ketrew_pure.Program.t ]
(** Create a value [`Distributed_shell _] to feed to {!create},
    see {!Edsl.yarn_distributed_shell}. *)

val create :
  ?host:Ketrew_pure.Host.t ->
  ?daemonize_using:[ `Nohup_setsid | `Python_daemon ] ->
  ?daemon_start_timeout: float ->
  [ `Distributed_shell of distributed_shell_parameters * Ketrew_pure.Program.t
  | `Yarn_application of Ketrew_pure.Program.t ] ->
  [> `Long_running of string * string ]
(** Create a “long-running” {!Ketrew_pure.Target.build_process} (run parameters
    are already serialized), see {!Edsl.yarn_application}. *)
end
module Long_running : sig (* manual one *)
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

(** Definition of the interface required from “long-running task” plugins. *)

open Ketrew_pure.Internal_pervasives
open Unix_io

(** The module type [LONG_RUNNING] defines the interface for plugins. *)
module type LONG_RUNNING = sig

  type run_parameters
  (** Hidden type kept serialized by the engine. *)

  val name: string
  (** The (unique) name of the plugin. *)

  val serialize: run_parameters -> string
  (** Serialize the run parameters for storage by the engine. *)

  val deserialize_exn: string -> run_parameters
  (** Deserialize the run parameters from a string; the engine guaranties
      that [deserialize_exn] will be called on the result of {!serialize};
      and assumes that no exception will be thrown in that case. *)

  val start: run_parameters ->
    (run_parameters, Host_io.Error.classified) Deferred_result.t
  (** Start the long-running computation, the returned [run_parameters] will be
      stored and used for the first call to {!update}. *)

  val update: run_parameters ->
    ([`Succeeded of run_parameters
     | `Failed of run_parameters * string
     | `Still_running of run_parameters], Host_io.Error.classified) Deferred_result.t
  (** Check and update the status of the long-running job. Again, is
      [`Still_running rp] is returned, the next call to {!update} (or {!kill})
      will receive those parameters. *)

  val kill: run_parameters ->
    ([`Killed of run_parameters], Host_io.Error.classified) Deferred_result.t
  (** Kill the long-running computation. *)

  val log: run_parameters -> (string * Log.t) list
  (** Get a list of things to display. *)

  val additional_queries : run_parameters -> (string * Log.t) list
  (** List of potential [(query, description)] pairs that can be passed
      to {!query}. *)

  val query: run_parameters -> string -> (string, Log.t) Deferred_result.t
  (** Perform a query. *)
end
end
