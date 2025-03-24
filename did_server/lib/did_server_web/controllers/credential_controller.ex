defmodule DidServerWeb.CredentialController do
  @moduledoc """
  See https://www.spruceid.dev/didkit/didkit-examples/core-functions-http
  """
  use DidServerWeb, :controller

  alias DidServerWeb.ErrorJSON

  def example(conn, %{"issuer" => issuer, "subject_id" => subject_id} = _params) do
    conn
    |> render("example_credential.json", issuer: issuer, subject_id: subject_id)
  end

  def issue(conn, %{"credential" => credential} = params) do
    option_params = Map.get(params, "options", %{})

    options =
      CryptoUtils.to_keyword_list(option_params, [
        :proof_format,
        :proof_purpose,
        :verification_method
      ])

    case Integrity.Credential.sign(credential, DidServer.AgentKeyStore, nil, options) do
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

  def verify(conn, %{"credential" => _credential} = _params) do
    conn
    |> put_status(500)
    |> put_view(ErrorJSON)
    |> render("500.json", detail: "Unimplemented")
  end
end
