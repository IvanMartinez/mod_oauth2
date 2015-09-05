{% extends "base.tpl" %}

{% block title %}{_ Authorize this request _}{% endblock %}

{% block content %}
    <div id="content" class="zp-100">
        <h1>{_ Allow _} {{ client.application_title|default:_"Untitled" }}?</h1>

        <p>{_ The application _} <em>{{ client.application_title|default:_"Untitled" }}</em> {_ wants to access your account. _}</p>

        {% if client.application_descr %}
            <p>{{ client.application_descr }}</p>
        {% endif %}

        {% if client.application_uri %}
            <p><a href="{{ client.application_uri }}">{_ More information about this program _}</a></p>
        {% endif %}

        <p>{_ This application wants access to the following services: _}</p>
        <ul>
            {% for perm in m.oauth2_perms.humanreadable[client.id] %}
                <li>{{ perm.desc }}</li>
            {% endfor %}
        </ul>

        <!-- FIXME: Show information about how this application will use your account. -->

        <form method="post">
            <div class="form-group">
                <button type="submit" class="btn btn-primary">{_ Allow! _}</button>
                <button type="reset" class="btn btn-default">{_ Disallow _}</button>
            </div>
        </form>

    </div>
{% endblock %}

