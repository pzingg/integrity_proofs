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

  @update_params %{
    "type " => "log_operation",
    "handle" => "at://alice.bsky.social",
    "signingKey" => elem(@signing_keypair, 0),
    "recoveryKey" => elem(@recovery_keypair, 0),
    "service" => "https://pds.example.com"
  }

  test "GET /plc/:did", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}")

    assert %{
             "id" => document_did,
             "alsoKnownAs" => ["at://bob.bsky.social"]
           } = json_response(conn, 200)

    assert document_did == did
  end

  test "GET /plc/:did/data", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}/data")

    assert %{
             "type" => "create",
             "handle" => "at://bob.bsky.social"
           } = json_response(conn, 200)
  end

  test "GET /plc/:did/log", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}/log")

    ops = json_response(conn, 200)
    assert is_list(ops)
    assert %{"did" => op_did} = List.last(ops)
    assert op_did == did
  end

  test "GET /plc/:did/log/audit", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}/log/audit")

    ops = json_response(conn, 200)
    assert is_list(ops)
    assert %{"did" => op_did} = List.last(ops)
    assert op_did == did
  end

  test "GET /plc/:did/log/last", %{conn: conn} do
    assert %{did: did} = operation_fixture()

    conn = get(conn, ~p"/plc/#{did}/log/last")

    assert %{"did" => op_did} = json_response(conn, 200)
    assert op_did == did
  end

  describe "POST /plc dids" do
    test "creates a new did", %{conn: conn} do
      {conn, _did} = post_genesis_op(conn)
      assert "" = json_response(conn, 200)
    end

    test "fails if same did attempted twice", %{conn: conn} do
      {conn, _} = post_genesis_op(conn)
      {conn, _} = post_genesis_op(conn)

      assert %{"errors" => %{"detail" => "create operation not allowed for an existing did"}} =
               json_response(conn, 400)
    end

    test "updates a handle", %{conn: conn} do
      {conn, did} = post_genesis_op(conn)
      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = Map.merge(@update_params, %{"signer" => @signer, "prev" => prev})
      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" = json_response(conn, 200)

      conn = get(conn, ~p"/plc/#{did}/data")
      assert %{"alsoKnownAs" => ["at://alice.bsky.social"]} = json_response(conn, 200)
    end

    test "tombstones a DID", %{conn: conn} do
      {conn, did} = post_genesis_op(conn)
      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = %{
        "type" => "plc_tombstone",
        "signer" => @signer,
        "prev" => prev
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" = json_response(conn, 200)

      conn = get(conn, ~p"/plc/#{did}/data")
      assert json_response(conn, 404)
    end
  end

  def post_genesis_op(conn) do
    did = CryptoUtils.Did.did_for_create_op(@create_params)

    params = Map.put(@create_params, "signer", @signer)
    {post(conn, ~p"/plc/#{did}", params), did}
  end
end
