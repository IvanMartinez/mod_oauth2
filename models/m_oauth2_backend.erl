%% @author Ivan Martinez <https://github.com/IvanMartinez>
%% @copyright 2013 author
%% @doc Database functions for the OAuth2 library.

%% Copyright 2013 Ivan Martinez
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%% 
%%     http://www.apache.org/licenses/LICENSE-2.0
%% 
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(m_oauth2_backend).

-behaviour(oauth2_backend).


-include("../include/oauth2_request.hrl").

%%% API
-export([add_resowner/2, add_resowner/3, delete_resowner/1, 
         add_client/4, delete_client/1]).

%%% OAuth2 backend functionality
-export([authenticate_user/2, 
         authenticate_client/2, 
         associate_access_code/3, 
         associate_access_token/3,
         associate_refresh_token/3, 
         resolve_access_code/2, 
         resolve_access_token/2, 
         resolve_refresh_token/2, 
         revoke_access_code/2, 
         revoke_access_token/2, 
         revoke_refresh_token/2, 
         get_client_identity/2, 
         get_redirection_uri/2,  
         verify_redirection_uri/3, 
         verify_client_scope/3,
         verify_resowner_scope/3, 
         verify_scope/3
        ]).

-define(ACCESS_CODE_TABLE, access_codes).
-define(ACCESS_TOKEN_TABLE, access_tokens).
-define(REFRESH_TOKEN_TABLE, refresh_tokens).
-define(USER_TABLE, users).
-define(CLIENT_TABLE, clients).
-define(REQUEST_TABLE, requests).

%%20:43:37.149 [error] CRASH REPORT Process <0.544.0> with 0 neighbours exited with reason: bad argument in call to ets:new(access_codes, [named_table,public]) in m_oauth2_backend:'-start/0-fun-0-'/1 line 76 in gen_server:init_it/6 line 328

-define(TABLES, [?ACCESS_CODE_TABLE,
                 ?ACCESS_TOKEN_TABLE,
                 ?REFRESH_TOKEN_TABLE,
                 ?USER_TABLE,
                 ?CLIENT_TABLE,
                 ?REQUEST_TABLE]).

-record(client, {
          client_id     :: binary(),
          client_secret :: binary(),
          redirect_uri  :: binary(),
          scope         :: [binary()]
         }).

-record(resowner, {
          username  :: binary(),
          password  :: binary(),
          scope     :: [binary()]
         }).

%%%===================================================================
%%% API
%%%===================================================================

-spec add_resowner(Username, Password, Scope) -> ok when
    Username  :: binary(),
    Password  :: binary(),
    Scope     :: [binary()].
add_resowner(Username, Password, Scope) ->
    put(?USER_TABLE, Username, #resowner{username = Username, 
                                         password = Password, scope = Scope}),
    ok.

-spec add_resowner(Username, Password) -> ok when
    Username :: binary(),
    Password :: binary().
add_resowner(Username, Password) ->
    add_resowner(Username, Password, []),
    ok.

-spec delete_resowner(Username) -> ok when
    Username :: binary().
delete_resowner(Username) ->
    delete(?USER_TABLE, Username),
    ok.

-spec add_client(Id, Secret, RedirectURI, Scope) -> ok when
    Id          :: binary(),
    Secret      :: binary(),
    RedirectURI :: binary(),
    Scope       :: [binary()].
add_client(Id, Secret, RedirectURI, Scope) ->
    put(?CLIENT_TABLE, Id, #client{client_id = Id,
                                   client_secret = Secret,
                                   redirect_uri = RedirectURI,
                                   scope = Scope
                                  }),
    ok.

-spec delete_client(Id) -> ok when
    Id :: binary().
delete_client(Id) ->
    delete(?CLIENT_TABLE, Id),
    ok.

%%%===================================================================
%%% OAuth2 backend functions
%%%===================================================================

%% Users are already authenticated by Zotonic
authenticate_user(Id, Context) ->
    case z_db:assoc_props_row("
        SELECT id
            FROM rsc 
            WHERE id = $1 AND is_published = true", [Id], Context) of
        undefined ->
            {error, notfound};
        [{_, User}] ->
            {ok, {Context, User}}
    end.

authenticate_client({ClientId, ClientSecret}, Context) ->
    case get(?CLIENT_TABLE, ClientId) of
        {ok, #client{client_secret = ClientSecret} = Identity} ->
            {ok, {Context, Identity}};
        {ok, #client{client_secret = _WrongSecret}} ->
            {error, badsecret};
        _ ->
            {error, notfound}
    end.

associate_access_code(AccessCode, CodeContext, Context) ->
    put(?ACCESS_CODE_TABLE, AccessCode, CodeContext),
    {ok, Context}.

associate_access_token(AccessToken, TokenContext, Context) ->
    put(?ACCESS_TOKEN_TABLE, AccessToken, TokenContext),
    {ok, Context}.

associate_refresh_token(RefreshToken, TokenContext, Context) ->
    put(?REFRESH_TOKEN_TABLE, RefreshToken, TokenContext),
    {ok, Context}.

resolve_access_code(AccessCode, Context) ->
    case get(?ACCESS_CODE_TABLE, AccessCode) of
        {ok, Grant} ->
            {ok, {Context, Grant}};
        Error = {error, notfound} ->
            Error
    end.

resolve_access_token(AccessToken, Context) ->
    case get(?ACCESS_TOKEN_TABLE, AccessToken) of
        {ok, Grant} ->
            {ok, {Context, Grant}};
        Error = {error, notfound} ->
            Error
    end.

resolve_refresh_token(RefreshToken, Context) ->
    case get(?REFRESH_TOKEN_TABLE, RefreshToken) of
        {ok, Grant} ->
            {ok, {Context, Grant}};
        Error = {error, notfound} ->
            Error
    end.

%% @doc Revokes an access code AccessCode, so that it cannot be used again.
revoke_access_code(AccessCode, Context) ->
    delete(?ACCESS_CODE_TABLE, AccessCode),
    {ok, Context}.

%% Not implemented yet.
revoke_access_token(_AccessToken, _Context) ->
    {error, notfound}.

%% Not implemented yet.
revoke_refresh_token(_RefreshToken, _Context) ->
    {error, notfound}.

get_redirection_uri(ClientId, Context) ->
    case z_db:assoc_props_row("
        SELECT redirection_uri
            FROM oauth2_application_registry 
            WHERE client_id = $1 AND enabled = true", [ClientId], Context) of
        undefined ->
            {error, notfound};
        [{_, RedirectionUri}] ->
            {ok, {Context, RedirectionUri}}
    end.

get_client_identity(ClientId, Context) ->
    case z_db:assoc_props_row("
        SELECT *
            FROM oauth2_application_registry 
            WHERE client_id = $1 AND enabled = true", [ClientId], Context) of
        undefined ->
            {error, notfound};
        Identity ->
            {ok, {Context, Identity}}
    end.

verify_redirection_uri(_Client, undefined,
                       Context) ->
    {ok, Context};
verify_redirection_uri(_Client, <<>>,
                       Context) ->
    {ok, Context};
verify_redirection_uri(Client, Uri, Context) ->
    case proplists:get_value(redirection_uri, Client) of
        Uri ->
            {ok, Context};
        _ ->
            {error, baduri}
    end.

verify_client_scope(#client{scope = RegisteredScope}, Scope, Context) ->
    verify_scope(RegisteredScope, Scope, Context).

%% Zotonic users don't have scopes
verify_resowner_scope(_Id, Scope, Context) ->
    {ok, {Context, Scope}}.

verify_scope(RegisteredScope, undefined, Context) ->
    {ok, {Context, RegisteredScope}};
verify_scope(_RegisteredScope, [], Context) ->
    {ok, {Context, []}};
verify_scope([], _Scope, _Context) ->
    {error, invalid_scope};
verify_scope(RegisteredScope, Scope, Context) ->
    case oauth2_priv_set:is_subset(oauth2_priv_set:new(Scope), 
                                   oauth2_priv_set:new(RegisteredScope)) of
        true ->
            {ok, {Context, Scope}};
        false ->
            {error, badscope}
    end.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% @todo: to be deleted
get(Table, Key) ->
    case ets:lookup(Table, Key) of
        [] ->
            {error, notfound};
        [{_Key, Value}] ->
            {ok, Value}
    end.

put(Table, Key, Value) ->
    ok.
    %ets:insert(Table, {Key, Value}).

delete(Table, Key) ->
    ok.
    %ets:delete(Table, Key).

