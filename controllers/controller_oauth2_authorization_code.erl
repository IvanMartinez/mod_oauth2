%% @author Ivan Martinez <https://github.com/IvanMartinez>
%% @copyright 2013 author
%% @doc Implements RFC6749 4.1 Authorization Code Grant, step 1 of 3.

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

-module(controller_oauth2_authorization_code).

-author("Ivan Martinez <https://github.com/IvanMartinez>").

-export([init/1,
         allowed_methods/2, 
         is_authorized/2,
         malformed_request/2,
         process_post/2,
         to_html/2]).

-include_lib("controller_webmachine_helper.hrl").
-include_lib("include/zotonic.hrl").


%% ====================================================================
%% API functions
%% ====================================================================


init(_Args) -> 
    {ok, []}.


allowed_methods(ReqData, Context) ->
    {['GET', 'POST', 'HEAD'], ReqData, Context}.


is_authorized(ReqData, Context) ->
    Context1 = ?WM_REQ(ReqData, Context),
    Context2 = z_context:ensure_all(Context1),
    z_acl:wm_is_authorized(z_auth:is_auth(Context2), Context2).


malformed_request(ReqData, _Context) ->
    Context  = z_context:new(ReqData, ?MODULE),
    z_context:lager_md(Context),
    Context2 = z_context:ensure_qs(Context),
    Params = wrq:req_qs(ReqData),
    ResponseType = oauth2_wrq:get_response_type(Params),
    ClientId = oauth2_wrq:get_client_id(Params),
    Uri = oauth2_wrq:get_redirect_uri(Params),
    Scope = oauth2_wrq:get_scope(Params),
    State = oauth2_wrq:get_state(Params),
    Context3 = z_context:set([{response_type, ResponseType},
                              {client_id, ClientId},
                              {redirect_uri, Uri},
                              {scope, Scope},
                              {state, State}], Context2),
    if
        ResponseType == undefined ->
            {true, ReqData, Context};
        ClientId == undefined ->
            {true, ReqData, Context};
        Uri == undefined ->
            %% @todo 4.1.1 of the spec says the redirection URI is optional, 
            %% but it's not clear about what to do when it is missing and it
            %% is difficult to implement with the current API of kivra/ouauth2.
            {true, ReqData, Context};
        true ->
            {false, ReqData, Context3}
    end.


-spec to_html(ReqData   :: #wm_reqdata{},
              Context   :: term()) ->
        {{halt, pos_integer()}, #wm_reqdata{}, _}.
to_html(ReqData, Context) ->
    Context1 = ?WM_REQ(ReqData, Context),
    Context2 = z_context:ensure_all(Context1),
    ResponseType = z_context:get(response_type, Context2),
    ClientId = z_context:get(client_id, Context2),
    _RedirectURI = z_context:get(redirect_uri, Context2),
    _Scope = z_context:get(scope, Context2),
    _State = z_context:get(state, Context2),
    case m_oauth2_backend:get_client_identity(ClientId, Context2) of
        {error, undefined} ->
           oauth2_wrq:json_error_response(ReqData, unauthorized_client,
                                           Context2);
        {ok, Client} ->
            Vars = [ {client, Client},
                     {response_type, ResponseType} ],
            Html = z_template:render("oauth2_authorize.tpl", Vars, Context2),
            {Result, ResultContext} = z_context:output(Html, Context2),
            Reply = ?WM_REPLY(Result, ResultContext),
            Reply
    end.


-spec process_post(ReqData   :: #wm_reqdata{},
                   Context   :: term()) ->
        {{halt, pos_integer()}, #wm_reqdata{}, _}.
process_post(ReqData, Context) ->
    Context1 = ?WM_REQ(ReqData, Context),
    Context2 = z_context:ensure_all(Context1),
    ResponseType = z_context:get(response_type, Context2),
    ClientId = z_context:get(client_id, Context2),
    RedirectURI = z_context:get(redirect_uri, Context2),
    Scope = z_context:get(scope, Context2),
    State = z_context:get(state, Context2),
    OwnerCredentials = z_acl:user(Context2),
    case ResponseType of
        code ->
            case oauth2:authorize_code_request(OwnerCredentials,
                                               ClientId,
                                               RedirectURI,
                                               Scope, Context2) of
                {ok, {_AppContext, Authorization}} ->
                    {ok, {_AppContext2, Response}} = 
                        oauth2:issue_code(Authorization, Context2),
                    {ok, Code} = oauth2_response:access_code(Response),
                    oauth2_wrq:redirected_authorization_code_response(
                        ReqData, RedirectURI, Code, State, Context2);
                {error, unauthorized_client} ->
                    %% cliend_id is not registered or redirection_uri is not 
                    %% valid
                    oauth2_wrq:json_error_response(ReqData, unauthorized_client, 
                                                   Context2);
                {error, Error} ->
                    oauth2_wrq:redirected_error_response(
                        ReqData, RedirectURI, Error, State, Context2)
            end;
        _ ->
            oauth2_wrq:redirected_error_response(
                ReqData, RedirectURI, unsupported_response_type, State, 
                Context2)
   end.
