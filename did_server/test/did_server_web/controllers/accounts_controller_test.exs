defmodule DidServerWeb.AccountsControllerTest do
  use DidServerWeb.ConnCase

  import DidServer.AccountsFixtures

  alias DidServer.Accounts.Account

  test "gets actor JSON data", %{conn: conn} do
    user = account_fixture()
    ap_id = Account.ap_id(user)
    handle = Account.domain_handle(user)

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> get(~p"/users/#{handle}")

    assert %{"type" => "Person", "id" => ^ap_id} = json_response(conn, 200)
  end

  test "gets actor HTML data", %{conn: conn} do
    user = account_fixture()
    handle = Account.domain_handle(user)

    conn =
      conn
      |> put_req_header("accept", "text/html")
      |> get(~p"/users/#{handle}")

    ap_id = Account.ap_id(user)
    assert html_response(conn, 200) =~ ap_id
  end

  test "gets profile HTML data", %{conn: conn} do
    user = account_fixture()
    handle = Account.domain_handle(user)

    conn =
      conn
      |> put_req_header("accept", "text/html")
      |> get(~p"/users/#{handle}/profile")

    ap_id = Account.ap_id(user)
    assert html_response(conn, 200) =~ ap_id
  end

  test "gets 404 for a non-existent user profile", %{conn: conn} do
    conn =
      conn
      |> put_req_header("accept", "text/html")
      |> get(~p"/users/notauser-/profile")

    assert html_response(conn, 404) =~ "Not Found"
  end
end
