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

  @signing_key "did:key:z7r8oofvCWdL3Y8TD3NuBsKiYKz6REqmkNteXjmhdXrGMA6w4TgiEEgA3YhgJy2gLPKygzvVUgoqEcLDd2Vtn5dpPCWoX"
  @signing_keypair [
    @signing_key,
    "ecdsa",
    <<227, 81, 77, 119, 225, 162, 50, 158, 96, 223, 15, 66, 246, 57, 87, 47, 176, 116, 78, 73, 21,
      219, 250, 109, 220, 154, 236, 171, 203, 29, 180, 100>>,
    "secp256k1"
  ]

  @recovery_key "did:key:z7r8oszBBiWkYzbhCu7tqABAwXW5ppVp9TFtLf6YnmP7M8KpjaNrE31PzQWSA7rxoJeuDBPMY9LH1DSHqQ26Nc2XZSAHv"
  @signer [
    @recovery_key,
    "ecdsa",
    <<34, 223, 210, 210, 107, 172, 126, 2, 107, 67, 41, 21, 117, 47, 136, 212, 69, 148, 181, 144,
      114, 250, 75, 19, 27, 170, 84, 119, 164, 166, 123, 57>>,
    "secp256k1"
  ]

  @operation_attrs %{
    signingKey: @signing_key,
    recoveryKey: @recovery_key,
    signer: @signer,
    handle: "bob.bsky.social",
    service: "https://pds.example.com"
  }

  def recovery_keypair_fixture(), do: @signer
  def signing_keypair_fixture(), do: @signing_keypair

  def operation_fixture(attrs \\ @operation_attrs) do
    {:ok, %{operation: op}} =
      attrs
      |> Enum.into(%{})
      |> DidServer.Log.create_operation()

    op
  end
end
