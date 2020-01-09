-module(acmerl_challenge_fail).
-behaviour(acmerl_challenge).
-export([challenge_type/0, deploy/2, remove/2]).

challenge_type() -> <<"http-01">>.

deploy(_,_) -> {ok, ignored}.

remove(_,_) -> ok.
