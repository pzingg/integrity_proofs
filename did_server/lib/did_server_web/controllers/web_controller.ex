defmodule DidServerWeb.WebController do
  use DidServerWeb, :controller

  alias DidServerWeb.ErrorJSON

  # TODO get domain from config
  @domain "example.com"

  def domain_did(conn, _params) do
    %{username: "admin", domain: @domain}
    |> DidServer.Log.did_document_for_user()
    |> case do
      doc when is_map(doc) ->
        render(conn, :show, document: doc)

      _ ->
        conn
        |> put_status(404)
        |> put_view(ErrorJSON)
        |> render("404.json")
    end
  end

  def show(conn, %{"path" => path}) do
    if Enum.count(path) > 1 && List.last(path) == "did.json" do
      with %{username: _username, domain: _domain} = user <- parse_user(path),
           doc when is_map(doc) <- DidServer.Log.did_document_for_user(user) do
        render(conn, :show, document: doc)
      else
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

  defp parse_user(path) do
    name =
      case path do
        ["users", username, "did.json"] -> username
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
end
