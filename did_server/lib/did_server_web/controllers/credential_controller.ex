defmodule DidServerWeb.CredentialController do
  @moduledoc """
  See https://www.spruceid.dev/didkit/didkit-examples/core-functions-http
  """
  use DidServerWeb, :controller

  require Logger

  def issue(conn, _params) do
    issue_credential(conn, conn.body_params)
  end

  def verify(conn, _params) do
    verify_credential(conn, conn.body_params)
  end

  def issue_credential(conn, %{"credential" => credential} = body_params) do
    option_params = Map.get(body_params, "options", %{})

    options =
      CryptoUtils.to_keyword_list(option_params, [
        :proof_format,
        :proof_purpose,
        :verification_method
      ])

    case Integrity.Credential.sign(credential, DidServer.KeyStore, nil, options) do
      {:ok, signed_credential} ->
        conn
        |> json(signed_credential)

      {:error, %{status_code: status_code, reason: reason}} ->
        conn
        |> put_status(status_code)
        |> put_view(ErrorJSON)
        |> render("#{status_code}.json", detail: reason)
    end
  end

  defp verify_credential(conn, _body_params) do
    conn
    |> put_status(500)
    |> put_view(ErrorJSON)
    |> render("500.json", detail: "Unimplemented")
  end
end
