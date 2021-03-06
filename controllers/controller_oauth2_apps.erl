%% @author Arjan Scherpenisse <arjan@scherpenisse.net>
%% @copyright 2009 Arjan Scherpenisse <arjan@scherpenisse.net>
%% Date: 2009-10-01
%% @doc Authorizing an OAuth access key

%% Copyright 2009 Arjan Scherpenisse
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

%% Doesn't seem related to the flow, it handles the admin operations.

-module(controller_oauth2_apps).
-author("Arjan Scherpenisse <arjan@scherpenisse.net>").

-export([
         is_authorized/2,
         event/2
]).

-include_lib("controller_html_helper.hrl").


is_authorized(ReqData, Context) ->
    z_admin_controller_helper:is_authorized(mod_oauth2, ReqData, Context).


html(Context) ->
    Html = z_template:render("oauth2_apps.tpl", [{page_admin_oauth, true}], Context),
	z_context:output(Html, Context).



del_consumer(Id, Context) ->
    m_oauth2_app:delete_client(Id, Context),
    Html = z_template:render("_oauth2_apps_list.tpl", [], Context),
    Context1 = z_render:update("oauth-apps", Html, Context),
    z_render:wire({growl, [{text, "Application removed."}]}, Context1).



%%
%% Start add oauth application (consumer)
%%
event(#postback{message=start_add_app}, Context) ->
    z_render:dialog("Add application", "_oauth2_client_edit.tpl", [], Context);

%%
%% Start edit oauth application (consumer)
%%
event(#postback{message={start_edit_app, Arg}}, Context) ->
    Id = proplists:get_value(id, Arg),
    Client = m_oauth2_app:get_client(Id, Context),
    Vars = [{client, Client}],
    z_render:dialog("Edit application", "_oauth2_client_edit.tpl", Vars, Context);

%%
%% Consumer save handler
%%
event(#submit{message={consumer_save, Arg}}, Context) ->
    Title = z_context:get_q("zp-title", Context),
    Descr = z_context:get_q("zp-text", Context),
    URL = z_context:get_q("zp-url", Context),
    Redirection = z_context:get_q("zp-redirection", Context),
    Perms = z_context:get_q_all("zp-perm", Context),

    Context1 = case proplists:get_value(id, Arg) of
                   undefined ->
                       Client = m_oauth2_app:create_client(Title, URL, Descr, Redirection, Context),
                       m_oauth2_perms:set(proplists:get_value(id, Client), Perms, Context),
                       z_render:wire({growl, [{text, ?__("Created new application.", Context)}]}, Context);
                   
                   Id ->
                       m_oauth2_app:update_client(Id, [{application_title, Title},
                                                       {application_descr, Descr},
                                                       {application_uri, URL},
                                                       {redirection_uri, Redirection}], Context),
                       m_oauth2_perms:set(Id, Perms, Context),
                       z_render:wire({growl, [{text, ?__("Application details saved.", Context)}]}, Context)
    end,
    Html = z_template:render("_oauth2_apps_list.tpl", [], Context1),
    Context2 = z_render:update("oauth-apps", Html, Context1),
    z_render:wire({dialog_close, []}, Context2);


%%
%% Delete oauth application (consumer)
%%
event(#postback{message={start_del_app, Arg}}, Context) ->
    Id = proplists:get_value(id, Arg),
    Vars = [{id, Id}, {delete, true}],
    z_render:dialog(?__("Delete application", Context), "_oauth2_consumer_tokens.tpl", Vars, Context);


event(#postback{message={start_tokens, Arg}}, Context) ->
    Id = proplists:get_value(id, Arg),
    Vars = [{id, Id}],
    z_render:dialog(?__("Tokens", Context), "_oauth2_consumer_tokens.tpl", Vars, Context);
    

event(#postback{message={confirm_del_app, Arg}}, Context) ->
    Id = proplists:get_value(id, Arg),
    Context1 = z_render:wire({dialog_close, []}, Context),
    del_consumer(Id, Context1).
