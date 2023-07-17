defmodule DidServer.LogFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `DidServer.Log` context.
  """

  @doc """
  Generate a did.
  """
  def did_fixture(attrs \\ %{did: "did:plc:y54rrfl37i5wqztksze4bddl"}) do
    {:ok, did} =
      attrs
      |> Enum.into(%{})
      |> DidServer.Log.create_did()

    did
  end

  @signing_key "did:key:z7r8ophEwkLiGhGmrnin9ThrA2pS7NA76tSf8dDEZZHbZpwk7KKKqbfvSWt1jgvQtEsTMMeE8hvjQW4XuR3aEHKEkQgF6"
  @recovery_key "did:key:z7r8oqrsihsuZXwqLsSn3gdCAMy5uBg7beJZ73jkABERNGawEFzJfkC5Gn9uepGJ2m3yZkYEHgrHH9MTzHvPEH757JpNs"
  @signer [
    @signing_key,
    "ecdsa",
    <<42, 126, 190, 208, 196, 239, 16, 83, 187, 23, 182, 230, 215, 56, 175, 139, 174, 2, 108, 46,
      204, 90, 165, 72, 17, 108, 90, 137, 226, 35, 81, 87>>,
    "secp256k1"
  ]

  @operation_attrs %{
    signingKey: @signing_key,
    recoveryKey: @recovery_key,
    signer: @signer,
    handle: "bob.bsky.social",
    service: "https://pds.example.com"
  }

  def operation_fixture(attrs \\ @operation_attrs) do
    {:ok, %{operation: op}} =
      attrs
      |> Enum.into(%{})
      |> DidServer.Log.create_operation()
    op
  end
end
