defmodule DidServerWeb.PlcController do
  use DidServerWeb, :controller

  def info(conn, _params) do
    # HTTP temporary redirect to project git repo
    # res.redirect(302, 'https://github.com/bluesky-social/did-method-plc')
    render(conn, :info, version: DidServer.Application.version())
  end

  def health(conn, _params) do
    version = DidServer.Application.version()

    if health_check() do
      render(conn, :health, version: version)
    else
      conn
      |> put_status(503)
      |> render(:health, version: version, error: "Service Unavailable")
    end
  end

  defp health_check() do
    true
  end
end
