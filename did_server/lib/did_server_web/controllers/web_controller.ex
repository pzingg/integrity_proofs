defmodule DidServerWeb.WebController do
  use DidServerWeb, :controller

  alias DidServerWeb.ErrorJSON

  # TODO get domain from config
  @domain "example.com"

  def show_root(conn, _params) do
    doc =
      %{username: "admin", domain: @domain}
      |> did_document_for_user()

    render(conn, :show, document: doc)
  end

  def show(conn, %{"path" => path}) do
    if Enum.count(path) > 1 && List.last(path) == "did.json" do
      case parse_user(path) do
        %{username: username, domain: domain} = user ->
          doc = did_document_for_user(user)
          render(conn, :show, document: doc)

        _ ->
          conn
          |> put_status(404)
          |> put_view(ErrorJSON)
          |> render("404.json")
      end
    else
      conn
      |> put_status(400)
      |> put_view(ErrorJSON)
      |> render("400.json")
    end
  end

  def info(conn, _params) do
    render(conn, :info, version: DidServer.Application.version())
  end

  defp did_document_for_user(%{username: username, domain: domain} = user) do
    identifier = lookup_did_key(user)
    %{public_key_multibase: multibase_value} = DidServer.context_and_key_for_did!(identifier)

    DidServer.format_did_document!(identifier,
      multibase_value: multibase_value,
      signature_method_fragment: "keys-1",
      also_known_as: "#{username}@#{domain}"
    )
  end

  defp parse_user(path) do
    name =
      case path do
        ["user", username, "did.json"] -> username
        [username, "did.json"] -> username
        _ -> nil
      end
      |> valid_name()

    if is_nil(name) do
      nil
    else
      %{username: name, domain: @domain}
    end
  end

  defp valid_name(nil), do: nil

  defp valid_name(name) do
    case String.trim(name) do
      "" -> nil
      name -> name
    end
  end

  # TODO lookup did for registered user
  defp lookup_did_key(_user) do
    {pub, _priv} = CryptoUtils.Keys.generate_key_pair(:did_key, :ed25519)
    pub
  end
end