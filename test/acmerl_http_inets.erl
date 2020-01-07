-module(acmerl_http_inets).
-behaviour(acmerl_http).
-export([request/5]).

request(Method, Url, Headers, Body, _) ->
    request1( httpc_method(Method), binary_to_list(Url)
	    , [{binary_to_list(K), binary_to_list(V)} || {K,V} <- Headers]
	    , Body).

request1(post, Url, Headers, Body) ->
    resp(httpc:request(post, {Url, Headers, "application/jose+json", Body},
			   [], [{body_format, binary}]));
request1(Method, Url, Headers, _) ->
    resp(httpc:request(Method, {Url, Headers}, [], [{body_format, binary}])).

resp({ok, {{_HttpVersion, Status, _Reason}, Headers, Body}}) ->
    {ok, Status,
     [{list_to_binary(string:lowercase(K)), list_to_binary(V)} ||
	 {K,V} <- Headers], Body};
resp({error, _} = Err) ->
    Err.

httpc_method('HEAD') -> head;
httpc_method('GET') -> get;
httpc_method('POST') -> post.
