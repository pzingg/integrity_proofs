defmodule DidServerWeb.WebController do
  use DidServerWeb, :controller

  def info(conn, _params) do
    render(conn, :info, version: DidServer.Application.version())
  end
end
