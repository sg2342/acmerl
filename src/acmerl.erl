-module(acmerl).
-export([ new_client/2
        , new_account/2, new_account/3
        , account_info/1, account_key/1
        , import_account/1, export_account/1
        , new_order/3
        , order_authorizations/3
        , deploy_challenges/4
        , validate_challenges/4
	, finalize_and_fetch/4
        ]).
-export_type([ client_opts/0, client/0
             , account/0
             ]).

-type maybe(T) :: {ok, T} | {error, term()}.
-type client_opts() :: #{ http_module := module()
                        , http_opts => term()
                        , json_module := module()
                        , json_opts => term()
                        }.

-record(client, { directory :: acmerl_json:json_term()
                , http_client :: acmerl_http:client()
                }).
-record(account, { url :: binary()
                 , key :: acmerl_jose:key()
                 , info = #{} :: acmerl_json:json_term()
                 }).

-opaque client() :: #client{}.
-opaque account() :: #account{}.

% API

-spec new_client(binary(), client_opts()) -> maybe(client()).
new_client(DirectoryUrl, #{ http_module := HttpMod
                          , json_module := JsonMod
                          } = Opts) ->
    JsonCodec = {JsonMod, maps:get(json_opts, Opts, [])},
    HttpOpts = maps:get(http_opts, Opts, []),
    HttpClient = acmerl_http:new_client(HttpMod, HttpOpts, JsonCodec),

    case acmerl_http:get(HttpClient, DirectoryUrl) of
        {ok, _, Directory} ->
            {ok, #client{ http_client = HttpClient
                        , directory = Directory
                        }};
        {error, _} = Err ->
            Err
    end.

-spec new_account(client(), acmerl_json:json_term()) -> maybe(account()).
new_account(Client, AccountOpts) ->
    new_account(Client, AccountOpts, {new_key, 'ES256'}).

-spec new_account(client(), acmerl_json:json_term(), AccountKeyOpts) ->
    maybe(account())
      when AccountKeyOpts :: {new_key, acmerl_jose:algo_name()}
                           | {key, acmerl_jose:key()}.
new_account(
  #client{ directory = #{ <<"newAccount">> := NewAccountUrl
			, <<"newNonce">> := NonceUrl }
	 , http_client = HttpClient },
  AccountOpts, AccountKeyOpts
 ) ->
    AccountKey = create_account_key(AccountKeyOpts),
    Jwk = acmerl_jose:export_key(AccountKey, #{ with_private => false
                                              , with_algo => false
                                              }),
    ExtraHeaders = #{ <<"jwk">> =>  Jwk},
    case acmerl_http:post(HttpClient, NonceUrl, NewAccountUrl, AccountOpts,
			  AccountKey, ExtraHeaders) of
        {ok, Headers, Response} ->
            {ok, #account{ url = proplists:get_value(<<"location">>, Headers)
                         , key = AccountKey
                         , info = Response
                         }};
        {error, _} = Err ->
            Err
    end.

-spec account_info(account()) -> acmerl_json:json_term().
account_info(#account{info = Info}) -> Info.

-spec account_key(account()) -> acmerl_jose:key().
account_key(#account{key = Key}) -> Key.

-spec export_account(account()) -> acmerl_json:json_term().
export_account(#account{ url = AccountUrl
                       , key = AccountKey
                       }) ->
    Jwk = acmerl_jose:export_key(AccountKey, #{ with_private => true
                                              , with_algo => true
                                              }),
    Jwk#{<<"kid">> => AccountUrl}.

-spec import_account(acmerl_json:json_term()) -> maybe(account()).
import_account(#{<<"kid">> := AccountUrl} = Key) when is_binary(AccountUrl) ->
    case acmerl_jose:import_key(Key) of
        {ok, Jwk} ->
            Account = #account{ url = AccountUrl, key = Jwk },
            {ok, Account};
        {error, _} = Err ->
            Err
    end;
import_account(_) ->
    {error, malformed}.

-spec new_order(client(), account(), acmerl_json:json_term()) ->
    maybe(acmerl_json:json_term()).
new_order(
  #client{ directory = #{ <<"newOrder">> := NewOrderUrl } } = Client,
  #account{ } = Account,
  OrderOpts
 ) ->
    case post(Client, Account, NewOrderUrl, OrderOpts) of
        {ok, _, Order} -> {ok, Order};
        {error, _} = Err -> Err
    end.

-spec order_authorizations(client(), account(), acmerl_json:json_term()) ->
    maybe([acmerl_json:json_term()]).
order_authorizations(
  #client{ } = Client,
  #account{ } = Account,
  #{<<"authorizations">> := Authorizations}
 ) ->
    lists:foldl(
      fun(AuthzUrl, {ok, Acc}) ->
        case post_as_get(Client, Account, AuthzUrl) of
            {ok, _, Authz} -> {ok, [Authz | Acc]};
            {error, _} = Err -> Err
        end;
         (_, {error, _} = Err) ->
              Err
      end,
      {ok, []},
      Authorizations
     ).

-spec deploy_challenges(account(), acmerl_challenge:handler(),
			acmerl_json:codec(), [acmerl_json:json_term()]) ->
	  maybe([acmerl_challenge:deployed()]).
deploy_challenges(
  #account{ key = AccountKey },
  Handler, JsonCodec, Authorizations
) ->
    Thumbprint = acmerl_jose:thumbprint(AccountKey, JsonCodec),
    lists:foldl(
      fun(Auth, {ok, Deployed}) ->
        case acmerl_challenge:deploy(Handler, Thumbprint, Auth) of
	    {ok, {_Url, _RemoveArg} = D} -> {ok, [D|Deployed]};
	    {error, _} = Err ->
		remove_deployed(Deployed, Handler),
		Err
	      end;
	 (_, {error, _} = Err) ->
	      Err
      end,
      {ok, []},
      Authorizations
     ).

-spec validate_challenges(client(), account(), acmerl_challenge:handler(),
			  [acmerl_challenge:deployed()]) ->
	  ok | {error, term()}.
validate_challenges(
  #client {} = Client,
  #account {} = Account,
  Handler, Deployed
) ->
    R = lists:foldl(
	  fun({Url, _}, ok) -> poll_validation(0, Client, Account, Url);
	     (_, {error, _} = Err) -> Err end, ok, Deployed),
    remove_deployed(Deployed, Handler),
    R.
-spec finalize_and_fetch(client(), account(),
			 Order ::acmerl_json:json_term(), CSR :: binary()) ->
	  maybe(PEM :: binary()).
finalize_and_fetch(
  #client {} = Client,
  #account {} = Account,
  #{ <<"finalize">> := Url },
  CSR
 ) ->
    case post(Client, Account, Url, #{<<"csr">> => base64url:encode(CSR)}) of
	{ok, _, #{ <<"status">> := <<"valid">>
		 , <<"certificate">> := PemUrl }} ->
	    case post_as_get(Client, Account, PemUrl) of
		{ok, {certificate_chain, PEM}} -> {ok, PEM};
		{ok, _, R1} -> {error, {unexpected, R1}};
		{error, _} = Err1 -> Err1 end;
	{ok, _, R} -> {error, {unexpected, R}};
	{error, _} = Err -> Err end.

% Private

create_account_key({new_key, AlgoName}) -> acmerl_jose:generate_key(AlgoName);
create_account_key({key, Key}) -> Key.

post(
  #client{ http_client = HttpClient
         , directory = #{ <<"newNonce">> := NonceUrl }
	 },
  #account{ key = AccountKey
	  , url = AccountUrl },
  Url, Payload
 ) ->
    JwsHeaders = #{ <<"kid">> => AccountUrl },
    acmerl_http:post(HttpClient, NonceUrl, Url, Payload, AccountKey, JwsHeaders).

post_as_get(
  #client{ http_client = HttpClient
         , directory = #{ <<"newNonce">> := NonceUrl }
         },
  #account{ key = AccountKey
	  , url = AccountUrl },
  Url
 ) ->
    JwsHeaders = #{ <<"kid">> => AccountUrl },
    acmerl_http:post_as_get(HttpClient, NonceUrl, Url, AccountKey, JwsHeaders).

-define(MAX_POLL_COUNT, 5).
poll_validation(N, _, _, _) when N > ?MAX_POLL_COUNT ->
    {error, max_poll_count_exceeded};
poll_validation(N, Client, Account, Url) ->
    timer:sleep(timer:seconds(N)),
    case post_as_get(Client, Account, Url) of
	{ok, _, #{<<"status">> := <<"valid">>}} -> ok;
	{ok, _, #{<<"status">> := <<"pending">>}} ->
	    poll_validation(N + 1, Client, Account, Url);
	{ok, _, R} -> {error, {unexpected, R}};
	{error, _} = Err -> Err
    end.

remove_deployed(Deployed, Handler) ->
    lists:foreach(
      fun({_Url, RemoveArg}) ->
	      acmerl_challenge:remove(Handler, RemoveArg)
      end,
      Deployed
     ).
