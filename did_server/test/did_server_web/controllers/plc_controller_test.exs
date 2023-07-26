defmodule DidServerWeb.PlcControllerTest do
  use DidServerWeb.ConnCase

  import DidServer.LogFixtures

  alias CryptoUtils.Keys.Keypair

  @signing_keypair Keypair.generate(:secp256k1, :did_key)
  @signing_key Keypair.did(@signing_keypair)
  @rotation_key_1 Keypair.generate(:secp256k1, :did_key)
  @rotation_key_2 Keypair.generate(:secp256k1, :did_key)

  @create_v1_params %{
    "type" => "create",
    "handle" => "at://bob.bsky.social",
    "signingKey" => @signing_key,
    "recoveryKey" => Keypair.did(@rotation_key_1),
    "service" => "https://pds.example.com",
    "prev" => nil
  }

  @create_params %{
    "type" => "plc_operation",
    "handle" => "at://bob.bsky.social",
    "signingKey" => @signing_key,
    "rotationKeys" => [Keypair.did(@rotation_key_1), Keypair.did(@rotation_key_2)],
    "service" => "https://pds.example.com",
    "prev" => nil
  }

  describe "GET" do
    test "healthcheck succeeds when database is available", %{conn: conn} do
      conn = get(conn, ~p"/plc/_health")
      assert %{"version" => _vsn, "status" => "ok"} = json_response(conn, 200)
    end

    # TODO disable Ecto queries

    @tag :no_db
    test "healthcheck fails when database is unavailable", %{conn: conn} do
      _conn = get(conn, ~p"/plc/_health")
      # assert %{"status" => "failed"} = json_response(conn, 503)
    end

    test "retrieves the did doc", %{conn: conn} do
      assert %{did: did} = operation_fixture()

      conn = get(conn, ~p"/plc/#{did}")

      assert %{
               "id" => document_did,
               "alsoKnownAs" => ["at://bob.bsky.social"]
             } = json_response(conn, 200)

      assert document_did == did
    end

    test "retrieves did doc data", %{conn: conn} do
      assert %{did: did} = operation_fixture()

      conn = get(conn, ~p"/plc/#{did}/data")

      assert %{
               "type" => "plc_operation",
               "alsoKnownAs" => ["at://bob.bsky.social"]
             } = json_response(conn, 200)
    end

    test "retrieves the operation log", %{conn: conn} do
      assert %{did: did} = operation_fixture()

      conn = get(conn, ~p"/plc/#{did}/log")

      ops = json_response(conn, 200)
      assert is_list(ops)
      assert %{"did" => op_did} = List.last(ops)
      assert op_did == did
    end

    test "retrieves the auditable operation log", %{conn: conn} do
      assert %{did: did} = operation_fixture()

      conn = get(conn, ~p"/plc/#{did}/log/audit")

      ops = json_response(conn, 200)
      assert is_list(ops)
      assert %{"did" => op_did} = List.last(ops)
      assert op_did == did
    end

    test "retrieves the last operation in the log", %{conn: conn} do
      assert %{did: did} = operation_fixture()

      conn = get(conn, ~p"/plc/#{did}/log/last")

      assert %{"did" => op_did} = json_response(conn, 200)
      assert op_did == did
    end
  end

  describe "POST" do
    test "registers a did", %{conn: conn} do
      {conn, did} = post_genesis_op(conn)
      assert "" = json_response(conn, 200)
      assert verify_doc(conn, did)
    end

    test "still allows create v1s", %{conn: conn} do
      {:ok, did} = CryptoUtils.Did.did_for_create_params(@create_v1_params)
      params = Map.put(@create_v1_params, "signer", Keypair.to_json(@rotation_key_1))
      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" = json_response(conn, 200)
      assert verify_doc(conn, did, rotation_keys: [Map.get(params, "recoveryKey")])
    end

    test "fails if same did attempted twice", %{conn: conn} do
      {conn, _} = post_genesis_op(conn)
      {conn, _} = post_genesis_op(conn)

      assert %{"errors" => %{"detail" => message}} = json_response(conn, 400)
      assert String.starts_with?(message, "create operation not allowed for an existing did")
    end

    test "tombstones the did", %{conn: conn} do
      {conn, did} = post_genesis_op(conn)
      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = %{
        "type" => "plc_tombstone",
        "prev" => prev,
        "signer" => Keypair.to_json(@rotation_key_1)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" = json_response(conn, 200)

      conn = get(conn, ~p"/plc/#{did}/data")
      assert json_response(conn, 404)
    end

    test "does not allow key types that we do not support", %{conn: conn} do
      {conn, did} = post_genesis_op(conn)
      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      ed25519_key = "did:key:z6MkjwbBXZnFqL8su24wGL2Fdjti6GSLv9SWdYGswfazUPm9"

      params = %{
        "type" => "plc_operation",
        "signingKey" => ed25519_key,
        "prev" => prev,
        "signer" => Keypair.to_json(@rotation_key_1)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" == json_response(conn, 200)
    end

    test "can perform some updates", %{conn: conn} do
      {conn, did} = post_genesis_op(conn)

      signing_key = Keypair.generate(:secp256k1, :did_key) |> Keypair.did()
      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = %{
        "type" => "plc_operation",
        "signingKey" => signing_key,
        "prev" => prev,
        "signer" => Keypair.to_json(@rotation_key_1)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" == json_response(conn, 200)

      new_keypair = Keypair.generate(:secp256k1, :did_key)
      new_rotation_keys = [Keypair.did(new_keypair), Keypair.did(@rotation_key_2)]

      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = %{
        "type" => "plc_operation",
        "rotationKeys" => new_rotation_keys,
        "prev" => prev,
        "signer" => Keypair.to_json(@rotation_key_1)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" == json_response(conn, 200)

      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = %{
        "type " => "plc_operation",
        "alsoKnownAs" => ["at://alice.bsky.social"],
        "prev" => prev,
        "signer" => Keypair.to_json(new_keypair)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" = json_response(conn, 200)

      conn = get(conn, ~p"/plc/#{did}/data")
      assert %{"alsoKnownAs" => ["at://alice.bsky.social"]} = json_response(conn, 200)
    end

    test "rejects on bad updates", %{conn: conn} do
      {conn, did} = post_genesis_op(conn)

      signing_keypair = Keypair.generate(:secp256k1, :did_key)
      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = %{
        "type" => "plc_operation",
        "prev" => prev,
        "signingKey" => Keypair.did(signing_keypair),
        "signer" => Keypair.to_json(signing_keypair)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert %{"errors" => %{"detail" => message}} = json_response(conn, 400)
      assert String.starts_with?(message, "invalid signature")
    end

    test "allows for recovery through a forked history", %{conn: conn} do
      {conn, did} = post_genesis_op(conn)

      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = %{
        "type " => "plc_operation",
        "alsoKnownAs" => ["at://alice.bsky.social"],
        "prev" => prev,
        "signer" => Keypair.to_json(@rotation_key_1)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" == json_response(conn, 200)
      assert DidServer.Log.list_operations(did, false) |> Enum.count() == 2

      attacker_keypair = Keypair.generate(:secp256k1, :did_key)
      conn = get(conn, ~p"/plc/#{did}/log/last")
      %{"cid" => prev} = json_response(conn, 200)

      params = %{
        "type" => "plc_operation",
        "rotationKeys" => [Keypair.did(attacker_keypair)],
        "prev" => prev,
        "signer" => Keypair.to_json(@rotation_key_2)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" == json_response(conn, 200)
      assert DidServer.Log.list_operations(did, false) |> Enum.count() == 3

      new_keypair = Keypair.generate(:secp256k1, :did_key)
      new_rotation_keys = [Keypair.did(@rotation_key_1), Keypair.did(new_keypair)]

      # Use same prev as before
      params = %{
        "type" => "plc_operation",
        "rotationKeys" => new_rotation_keys,
        "prev" => prev,
        "signer" => Keypair.to_json(@rotation_key_1)
      }

      conn = post(conn, ~p"/plc/#{did}", params)
      assert "" == json_response(conn, 200)

      assert verify_doc(conn, did, rotation_keys: new_rotation_keys)
    end
  end

  def post_genesis_op(conn) do
    {:ok, did} = CryptoUtils.Did.did_for_create_params(@create_params)

    params = Map.put(@create_params, "signer", Keypair.to_json(@rotation_key_1))
    {post(conn, ~p"/plc/#{did}", params), did}
  end

  def verify_doc(conn, did, opts \\ []) do
    conn = get(conn, ~p"/plc/#{did}/data")
    doc = json_response(conn, 200)

    expected_rotation_keys =
      Keyword.get(opts, :rotation_keys, [
        Keypair.did(@rotation_key_1),
        Keypair.did(@rotation_key_2)
      ])

    rotation_keys = Map.get(doc, "rotationKeys")
    assert rotation_keys == expected_rotation_keys
    signing_key = get_in(doc, ["verificationMethods", "atproto"])
    assert signing_key == @signing_key
  end
end
