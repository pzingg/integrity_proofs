defmodule DidServerWeb.PlcControllerTest do
  use DidServerWeb.ConnCase

  import DidServer.LogFixtures

  @signing_keypair CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @recovery_keypair CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  @signer CryptoUtils.Keys.to_signer(@recovery_keypair)

  @create_params %{
    "type" => "create",
    "handle" => "at://bob.bsky.social",
    "signingKey" => elem(@signing_keypair, 0),
    "recoveryKey" => elem(@recovery_keypair, 0),
    "service" => "https://pds.example.com",
    "prev" => nil
  }

  test "GET /plc/:did", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}")

    assert %{
             "data" => %{
               "id" => document_did,
               "alsoKnownAs" => ["at://bob.bsky.social"]
             }
           } = json_response(conn, 200)

    assert document_did == did
  end

  test "GET /plc/:did/data", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}/data")

    assert %{
             "data" => %{
               "type" => "create",
               "handle" => "at://bob.bsky.social"
             }
           } = json_response(conn, 200)
  end

  test "GET /plc/:did/log", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}/log")

    assert %{"data" => ops} = json_response(conn, 200)
    assert %{"did" => op_did} = List.last(ops)
    assert op_did == did
  end

  test "GET /plc/:did/log/audit", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}/log/audit")

    assert %{"data" => ops} = json_response(conn, 200)
    assert %{"did" => op_did} = List.last(ops)
    assert op_did == did
  end

  test "GET /plc/:did/log/last", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}/log/last")

    assert %{"data" => %{"did" => op_did}} = json_response(conn, 200)
    assert op_did == did
  end

  describe "POST /plc dids" do
    test "creates a new did", %{conn: conn} do
      did = CryptoUtils.Did.did_for_create_op(@create_params)
      params = Map.put(@create_params, "signer", @signer)
      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" = json_response(conn, 200)
    end

    test "fails if same did attempted twice", %{conn: conn} do
      did = CryptoUtils.Did.did_for_create_op(@create_params)
      params = Map.put(@create_params, "signer", @signer)
      _ = post(conn, ~p"/plc/#{did}", params)

      assert_raise(CryptoUtils.Did.ImproperOperationError, fn ->
        post(conn, ~p"/plc/#{did}", params)
      end)
    end
  end
end
