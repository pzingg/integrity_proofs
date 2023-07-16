defmodule DidServerWeb.PlcController do
  use DidServerWeb, :controller

  alias DidServer.Log.Operation
  alias DidServerWeb.ErrorJSON

  def info(conn, _params) do
    # HTTP temporary redirect to project git repo
    # res.redirect(302, 'https://github.com/bluesky-social/did-method-plc')
    render(conn, :info, version: DidServer.Application.version())
  end

  def health(conn, _params) do
    version = DidServer.Application.version()

    if DidServer.Log.health_check() do
      render(conn, :health, version: version)
    else
      conn
      |> put_status(503)
      |> render(:health, version: version, error: "Service Unavailable")
    end
  end

  def show(conn, %{"did" => did}) do
    with %Operation{} = last <- DidServer.Log.last_op_for_did(did) do
      doc =
        DidServer.Log.Operation.to_data(last, did)
        |> CryptoUtils.Did.format_did_plc_document()

      conn
      |> put_resp_content_type("application/did+ld+json")
      |> render(:show, document: doc)
    else
      _ ->
        conn
        |> put_status(404)
        |> put_view(ErrorJSON)
        |> render("404.json")
    end
  end

  def new(conn, %{"did" => did} = params) do
    with {:ok, {_op, ^did}} <- DidServer.Log.create_operation(params) do
      render(:new, did: did)
    else
      {:error, %Ecto.Changeset{errors: [{field, {message, _keys}} | _]}} ->
        conn
        |> put_status(400)
        |> put_view(ErrorJSON)
        |> render("400.json", details: "#{field} #{message}")

      {:error, reason} ->
        conn
        |> put_status(400)
        |> put_view(ErrorJSON)
        |> render("400.json", details: reason)
    end
  end
end
