defmodule DidServerWeb.DidWebControllerTest do
  use DidServerWeb.ConnCase

  import DidServer.AccountsFixtures

  test "GET /.well-known/did.json", %{conn: conn} do
    {:ok, _user} =
      DidServer.Accounts.register_account(
        valid_account_attributes(username: "admin", domain: "example.com")
      )

    conn = get(conn, ~p"/.well-known/did.json")
    assert %{"id" => id} = json_response(conn, 200)
    assert id =~ "did:plc:"
  end
end
