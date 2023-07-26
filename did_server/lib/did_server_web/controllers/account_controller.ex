defmodule DidServerWeb.AccountController do
  use DidServerWeb, :controller

  alias DidServer.Accounts
  alias DidServerWeb.{ErrorHTML, ErrorJSON}

  def actor(conn, %{"handle" => handle}) do
    user = Accounts.get_user_by_identifier(handle)

    if is_nil(user) do
      render_not_found(conn, get_format(conn))
    else
      render(conn, :actor, %{user: user})
    end
  end

  def profile(conn, %{"handle" => handle}) do
    user = Accounts.get_user_by_identifier(handle)

    if is_nil(user) do
      render_not_found(conn, get_format(conn))
    else
      render(conn, :actor, %{user: user})
    end
  end

  defp render_not_found(conn, "json") do
    conn
    |> put_status(404)
    |> put_view(ErrorJSON)
    |> render("404.json")
  end

  defp render_not_found(conn, _) do
    conn
    |> put_status(404)
    |> put_view(ErrorHTML)
    |> render("404.html")
  end
end
