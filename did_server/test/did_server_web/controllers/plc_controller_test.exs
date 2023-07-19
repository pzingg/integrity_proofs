defmodule DidServerWeb.PlcControllerTest do
  use DidServerWeb.ConnCase

  test "GET /plc/:did", %{conn: conn} do
    import DidServer.LogFixtures
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}")

    assert %{"data" => %{"id" => document_did, "alsoKnownAs" => ["at://bob.bsky.social"]}} =
             json_response(conn, 200)

    assert document_did == did
  end
end
