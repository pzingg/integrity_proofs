defmodule DidServerWeb.PlcControllerTest do
  use DidServerWeb.ConnCase

  test "GET /:did", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert html_response(conn, 200) =~ "Peace of mind from prototype to production"
  end
end
