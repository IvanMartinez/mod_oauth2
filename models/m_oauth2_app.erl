%% @author Ivan Martinez <https://github.com/IvanMartinez>
%% @copyright 2014 Ivan Martinez, 2009 Arjan Scherpenisse
%% Date: 2004-01-01
%% @doc OAuth2; application (server) store.

%% Copyright 2014 Ivan Martinez, 2009 Arjan Scherpenisse
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

-module(m_oauth2_app).
-author("Ivan Martinez <https://github.com/IvanMartinez>").

-behaviour(gen_model).


-include_lib("zotonic.hrl").


-export([
         m_find_value/3,
         m_to_list/2,
         m_value/2,

         consumer_tokens/2,
         
         consumer_lookup/2,
         secrets_for_verify/4,
         check_nonce/5,
         request_token/2,
         authorize_request_token/3,
         exchange_request_for_access/2,

         get_request_token/2,

         create_client/5,
         update_client/3,
         get_client/2,
         delete_client/2
         ]).

-define(TS_SKEW, 600).


%% gen_model

%% @doc Fetch the value for the key from a model source
%% @spec m_find_value(Key, Source, Context) -> term()
m_find_value(info, #m{value=undefined} = M, _Context) ->
    M#m{value=info};
m_find_value(Id, #m{value=info}, Context) ->
    get_client(Id, Context);

m_find_value(tokens, #m{value=undefined} = M, _Context) ->
    M#m{value=tokens};
m_find_value(Id, #m{value=tokens}, Context) ->
    consumer_tokens(Id, Context).

%% @doc Transform a m_config value to a list, used for template loops
%% @spec m_to_list(Source, Context) -> list()
m_to_list(#m{value=undefined}, Context) ->
    all_apps(Context).

%% @doc Transform a model value so that it can be formatted or piped through filters
%% @spec m_value(Source, Context) -> term()
m_value(#m{value=undefined}, _Context) ->
    undefined;
m_value(#m{value=_Module}, _Context) ->
    undefined.
    


all_apps(Context) ->
    z_db:assoc_props("SELECT * FROM oauth2_application_registry WHERE user_id = $1 ORDER BY timestamp DESC",
                     [Context#context.user_id], Context).

consumer_tokens(Id, Context) ->
    z_db:assoc_props("SELECT * FROM oauth2_application_token 
                        WHERE application_id = $1 ORDER BY timestamp DESC",
                     [Id], Context).



%% 
%% Lookup a application in the application registry.
%%
%% Return a tuple: {Key, Secret, Signature method}
consumer_lookup(Key, Context) ->
    z_db:assoc_props_row("
        SELECT id, client_id, client_secret, redirection_uri
                FROM oauth2_application_registry 
                WHERE client_id = $1 AND enabled = true", [Key], Context).


secrets_for_verify(none, Consumer, _Token, Context) ->
    z_db:assoc_props_row("
        SELECT id, client_id, client_secret, redirection_uri
                FROM oauth2_application_registry
                WHERE client_id	= $1
                AND enabled = true", [proplists:get_value(client_id, Consumer)], Context);

secrets_for_verify(Type, Consumer, Token, Context) ->
    z_db:assoc_props_row("
        SELECT	tok.id AS id,
           application_id,
           app.user_id as user_id,
           client_id,
           client_secret,
           token,
           token_secret,
           tok.callback_uri
        FROM oauth2_application_registry app
           JOIN oauth2_application_token tok
           ON app.id = tok.application_id
               WHERE token_type	= $1
                 AND client_id	= $2
                 AND token			= $3
				 AND enabled		= true
                 AND token_ttl     >= NOW()", [Type, proplists:get_value(client_id, Consumer), Token], Context).


check_nonce(Consumer, Token, Timestamp, Nonce, Context) ->

    CKey = proplists:get_value(client_id, Consumer),
    TK = proplists:get_value(token, Token),
    TS = z_convert:to_integer(Timestamp),
    z_db:transaction(fun (C) -> check_nonce1(CKey, TK, TS, Nonce, C) end, Context).


check_nonce1(CKey, TK, TS, Nonce, Context) ->
    % Check timestamp
    TCheck = z_db:assoc_props_row("
                SELECT MAX(timestamp), MAX(timestamp) > TIMESTAMP 'epoch' + ($1) * INTERVAL '1 second' AS ok
						FROM oauth2_nonce
						WHERE client_id = $2
						  AND token        = $3
						", [TS + ?TS_SKEW, CKey, TK], Context),
    case TCheck of
        [{max, _}, {ok, true}] ->
            {false, "Timestamp is out of sequence.\n"};
        _ ->
            case z_db:assoc_props_row("SELECT 1 AS x FROM oauth2_nonce WHERE client_id = $1 AND token = $2 AND nonce = $3 AND timestamp = TIMESTAMP 'epoch' + ($4) * INTERVAL '1 second'",
                                      [CKey, TK, Nonce, TS], Context) of
                undefined ->
                    %% Safe to insert
                    z_db:q("INSERT INTO oauth2_nonce (client_id, token, timestamp, nonce) VALUES ($1, $2, TIMESTAMP 'epoch' + ($3) * INTERVAL '1 second', $4)",
                        [CKey, TK, TS, Nonce], Context),
                    %% Clean up all timestamps older than the one we just received
                    z_db:q("DELETE FROM oauth2_nonce WHERE client_id = $1 AND token = $2 AND timestamp < TIMESTAMP 'epoch' + $3 * INTERVAL '1 second'",
                           [CKey, TK, TS-?TS_SKEW], Context),
                    true;
                _ ->
                    {false, "Duplicate timestamp/nonce combination, possible replay attack. Request rejected.\n"}
            end
    end.


%% @TODO: Use a generator that doesn't include characters that have a
%% special meaning in URLs, such as + % ? = ...
generate_key() ->
    base64:encode_to_string(crypto:hash(sha, crypto:rand_bytes(100))).


%%
%% Create a request token for given consumer.
%%
request_token(Consumer, Context) ->
    case z_db:insert("oauth2_application_token", 
                [ {application_id, proplists:get_value(id, Consumer)},
                  {user_id, 1},
                  {token, generate_key()},
                  {token_secret, generate_key()},
                  {token_type, "request"},
                  {callback_uri, proplists:get_value(callback_uri, Consumer)}], Context) of
        {ok, Id} ->
            z_db:select("oauth2_application_token", Id, Context);
        _ ->
            undefined
    end.


authorize_request_token(Token, UserId, Context) ->
    z_db:update("oauth2_application_token", proplists:get_value(id, Token), [{authorized, true}, {user_id, UserId}], Context).


exchange_request_for_access(Token, Context) ->
    TokenId = proplists:get_value(id, Token),
    case z_db:assoc_props_row("SELECT id FROM oauth2_application_token WHERE
                                application_id = $1 AND
                                token = $2 AND
                                token_type = 'request' AND
                                authorized = true", [proplists:get_value(application_id, Token), proplists:get_value(token, Token)], Context) of
        [{id, TokenId}] ->
            z_db:update("oauth2_application_token", TokenId, 
                        [{token, generate_key()},
                         {token_secret, generate_key()},
                         {token_type, "access"}], Context),
            z_db:q("UPDATE oauth2_application_token SET timestamp = now() WHERE id = $1", [TokenId], Context),
            z_db:select("oauth2_application_token", TokenId, Context);

        _ ->
            {false, "Failed to exchange request token for access token.\n"}
    end.


%%
%% Get a token from the database.
%% 
get_request_token(Tok, Context) ->
    z_db:assoc_props_row("SELECT * FROM oauth2_application_token tok JOIN oauth2_application_registry app
                        ON (tok.application_id = app.id)
                        WHERE tok.token = $1 LIMIT 1" ,
                         [Tok], Context).

    
create_client(Title, URL, Desc, RedirectionURI, Context) ->
    case z_db:insert("oauth2_application_registry", 
                [ {user_id, Context#context.user_id},
                  {client_id, generate_key()},
                  {client_secret, generate_key()},
                  {enabled, true},
                  {redirection_uri, RedirectionURI},
                  {application_title, Title},
                  {application_uri, URL},
                  {application_descr, Desc},
                  {application_notes, ""},
                  {application_type, ""}], Context) of
        {ok, Id} ->
            {ok, C} = z_db:select("oauth2_application_registry", Id, Context),
            C;
        _ ->
            undefined
    end.

update_client(Id, Update, Context) ->
    z_db:update("oauth2_application_registry", Id, Update, Context).

get_client(Id, Context) ->
    {ok, C} = z_db:select("oauth2_application_registry", Id, Context),
    C.
    
delete_client(Id, Context) ->
    {ok, _} = z_db:delete("oauth2_application_registry", Id, Context).

