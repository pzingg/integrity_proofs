defmodule DidServerWeb.ServiceController do
  @moduledoc """
  From Pleroma: A lightweight social networking server
  Copyright © 2017-2021 Pleroma Authors <https://pleroma.social/>
  SPDX-License-Identifier: AGPL-3.0-only
  """

  use DidServerWeb, :controller

  require Logger

  alias DidServerWeb.{Utils, WebFinger}

  def nodeinfo(conn, _params) do
    endpoint_uri = DidServerWeb.Endpoint.url() |> Utils.to_uri()

    nodeinfo_version_url = Utils.base_uri(endpoint_uri, "/nodeinfo/2.0") |> URI.to_string()

    links = %{
      links: [
        %{
          rel: "http://nodeinfo.diaspora.software/ns/schema/2.0",
          href: nodeinfo_version_url
        }
      ]
    }

    conn
    |> put_resp_content_type("application/json")
    |> render(:nodeinfo, links: links)
  end

  def nodeinfo_version(conn, %{"version" => nodeinfo_version} = _params) do
    if nodeinfo_version == "2.0" do
      app_name = DidServer.Application.name()
      app_version = DidServer.Application.version()
      protocols = DidServer.Application.protocols()
      usage = DidServer.Accounts.usage()

      nodeinfo = %{
        version: nodeinfo_version,
        software: %{name: app_name, version: app_version},
        protocols: protocols,
        usage: usage,
        openRegistrations: false
      }

      conn
      |> render(:nodeinfo_version, nodeinfo: nodeinfo)
    else
      conn
      |> put_status(400)
      |> put_view(ErrorJSON)
      |> render("400.json", details: "Only version 2.0 is supported")
    end
  end

  def hostmeta(%Plug.Conn{} = conn, _params) do
    xml = WebFinger.host_meta()

    conn
    |> put_resp_content_type("application/xrd+xml")
    |> send_resp(200, xml)
  end

  def webfinger(%Plug.Conn{} = conn, %{"resource" => resource}) do
    format = get_format(conn)

    cond do
      format in ["xml", "xrd+xml"] ->
        with {:ok, response} <- WebFinger.webfinger(resource, :xml) do
          conn
          |> put_resp_content_type("application/xrd+xml")
          |> send_resp(200, response)
        else
          _ -> send_resp(conn, 404, "Resource not found")
        end

      format in ["json", "jrd+json"] ->
        with {:ok, response} <- WebFinger.webfinger(resource, :json) do
          json(conn, response)
        else
          _ ->
            conn
            |> put_status(404)
            |> json("Resource not found")
        end

      true ->
        Logger.error("webfinger bad format: #{inspect(format)}")
        send_resp(conn, 406, "Not acceptable")
    end
  end

  def webfinger(%Plug.Conn{} = conn, params) do
    Logger.error("webfinger bad params: #{inspect(params)}")
    send_resp(conn, 400, "Bad Request")
  end
end
