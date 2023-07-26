defmodule DidServerWeb.WebControllerTest do
  use DidServerWeb.ConnCase

  test "GET /.well-known/did.json", %{conn: conn} do
    conn = get(conn, ~p"/.well-known/did.json")
    assert %{"id" => id} = json_response(conn, 200)
    assert id =~ "did:key:z6"
  end
end
