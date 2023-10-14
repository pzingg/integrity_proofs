defmodule DidServerWeb.KeyStoreController do
  @moduledoc false

  use DidServerWeb, :controller

  alias DidServerWeb.ErrorJSON

  def new(conn, _params) do
    {did_key, private_key_pem, _, _} = CryptoUtils.Keys.generate_keypair(:ed25519, :did_key, :pem)
    _ = DidServer.AgentKeyStore.put(:user, did_key, private_key_pem)

    conn
    |> json(%{public_key: did_key, private_key: private_key_pem})
  end

  def create(conn, %{"private_key" => private_key_pem} = _params) do
    case CryptoUtils.Keys.decode_pem_ssh_file(private_key_pem, :openssh_key_v1, :did_key) do
      {:ok, did_key, _private_key} ->
        _ = DidServer.AgentKeyStore.put(:user, did_key, private_key_pem)

        conn
        |> json(%{public_key: did_key})

      _ ->
        conn
        |> put_status(400)
        |> put_view(ErrorJSON)
        |> render("400.json", detail: "PEM file could not be decoded")
    end
  end

  def show(conn, %{"public_key" => did_key} = _params) do
    private_key_pem =
      DidServer.AgentKeyStore.get(:user, did_key) ||
        DidServer.AgentKeyStore.get(:system, did_key)

    if is_nil(private_key_pem) do
      conn
      |> put_status(404)
      |> put_view(ErrorJSON)
      |> render("404.json")
    else
      conn
      |> json(%{private_key: private_key_pem})
    end
  end
end
