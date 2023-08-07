defmodule DidServer.IdentitiesTest do
  use DidServer.DataCase

  alias CryptoUtils.Keys.Keypair
  alias DidServer.Identities

  describe "keys" do
    alias DidServer.Identities.Key

    import DidServer.LogFixtures

    @invalid_attrs %{"did" => nil, "password" => nil}

    test "list_keys/0 returns all dids" do
      %{did: fixture_did} = key_fixture()
      found = Identities.list_keys() |> Enum.find(fn %Key{did: did} -> did == fixture_did end)
      assert %Key{} = found
    end

    test "get_key!/1 returns the did with given id" do
      %{did: did} = key_fixture()
      assert %Key{did: ^did} = Identities.get_key!(did)
    end

    test "create_key/1 succeeds with valid attributes" do
      did = "did:plc:y54rrfl37i5wqztksze4bddl"
      password = "bluesky"
      {:ok, %Key{did: ^did}} = Identities.create_key(%{did: did, password: password})
    end

    test "create_key/1 fails with invalid attributes" do
      {:error, _} = Identities.create_key(@invalid_attrs)
    end

    test "create_key/1 fails for an existing did" do
      %{did: did} = key_fixture()
      {:error, _} = Identities.create_key(%{did: did})
    end
  end
end
