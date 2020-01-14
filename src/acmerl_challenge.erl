-module(acmerl_challenge).
-export([deploy/3, remove/2]).

-export_type([remove_arg/0, deploy_arg/0, handler/0, deployed/0]).

-type deployed() :: { Url :: binary(), remove_arg() }.
-type handler() :: { Module :: module(), Opts :: term() }.
-type remove_arg() :: term().
-type deploy_arg() :: #{ identifier := binary()
		       , token := binary()
		       , key_auth := binary()}.

-callback challenge_type() -> binary().
-callback deploy(deploy_arg(), Opts :: term()) ->
    {ok, remove_arg()} | {error, term}.
-callback remove(remove_arg(), Opts :: term()) -> ok.

% API

-spec deploy(handler(), Thumbprint :: binary(),
	     Authorization :: acmerl_json:json_term()) ->
	  {ok, deployed()} |
	  {error, term()}.
deploy(
  {Handler, Opts}, Thumbprint,
  #{ <<"challenges">> := Challenges
   , <<"identifier">> := #{<<"value">> := Identifier}}
 ) ->
    Type = Handler:challenge_type(),
    L = lists:filter(fun(#{ <<"type">> := T }) -> T == Type end, Challenges),
    deploy1(L, {Handler, Opts}, Identifier, Thumbprint).

-spec remove(handler(), remove_arg()) -> ok.
remove({Handler, Opts}, Arg) -> Handler:remove(Arg, Opts).

% Private

deploy1([], _, _,_) -> {error, type_not_in_challenges};
deploy1([#{ <<"type">> := Type, <<"url">> := Url, <<"token">> := Token }|_],
	 {Handler, Opts}, Identifier, Thumbprint) ->
    KeyAuth = key_auth(Type, <<Token/binary, $., Thumbprint/binary>>),
    Arg = #{ identifier => Identifier
	   , key_auth => KeyAuth
	   , token => Token },
    deploy2(Handler:deploy(Arg, Opts), Url).

deploy2({ok, RemoveArg}, Url) -> {ok, {Url, RemoveArg}};
deploy2({error, _} = Error, _) -> Error.

key_auth(<<"dns-01">>, V) -> base64url:encode(crypto:hash(sha256, V));
key_auth(<<"tls-alpn-01">>, V) -> crypto:hash(sha256, V);
key_auth(_, V) -> V.
