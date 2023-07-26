defmodule DidServerWeb.AccountControllerTest do
  use DidServerWeb.ConnCase

  import DidServer.AccountsFixtures

  alias DidServer.Accounts.User

  test "gets actor JSON data", %{conn: conn} do
    %{username: username} = user = user_fixture()

    handle = User.domain_handle(user)

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> get(~p"/user/#{handle}")

    assert %{"username" => ^username} = json_response(conn, 200)
  end

  test "gets actor HTML data", %{conn: conn} do
    user = user_fixture()
    handle = User.domain_handle(user)
    conn = get(conn, ~p"/user/#{handle}")

    ap_id = User.ap_id(user)
    assert html_response(conn, 200) =~ ap_id
  end

  test "gets profile JSON data", %{conn: conn} do
    %{username: username} = user = user_fixture()
    handle = User.domain_handle(user)

    conn =
      conn
      |> put_req_header("accept", "application/json")
      |> get(~p"/user/#{handle}/profile")

    assert %{"username" => ^username} = json_response(conn, 200)
  end

  test "gets profile HTML data", %{conn: conn} do
    user = user_fixture()
    handle = User.domain_handle(user)
    conn = get(conn, ~p"/user/#{handle}/profile")

    ap_id = User.ap_id(user)
    assert html_response(conn, 200) =~ ap_id
  end

  test "gets 404 for a non-existent user profile", %{conn: conn} do
    conn = get(conn, ~p"/user/notauser-/profile")

    assert html_response(conn, 404) =~ "Not Found"
  end
end
