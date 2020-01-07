-module(acmerl_json_jsone).
-behaviour(acmerl_json).

-export([new/0]).

-export([encode/2, decode/2]).

new() -> {?MODULE, []}.

encode(Term, _) -> jsone:encode(Term).

decode(Term, _) -> jsone:decode(Term).
