defmodule DidServer.LogFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `DidServer.Log` context.
  """

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

  @did_password "bluesky"
  @example_domain "example.com"

  @operation_attrs %{
    type: "create",
    signingKey: @signing_key,
    recoveryKey: @recovery_key,
    signer: @signer,
    handle: "bob.bsky.social",
    service: "https://pds.example.com",
    password: @did_password
  }

  def recovery_keypair_fixture, do: @signer
  def signing_keypair_fixture, do: @signing_keypair
  def unique_account_username, do: "user#{System.unique_integer()}"
  def valid_did_password, do: @did_password

  def server_signing_key(path \\ nil) do
    path = path || "./test/support/fixtures/server.key"
    {:ok, pem} = File.read(path)
    {:ok, keypair} = CryptoUtils.Keys.Keypair.decode_pem_public_key(pem)
    keypair
  end

  def valid_create_op_attributes(attrs \\ %{}) do
    username = unique_account_username()
    domain = @example_domain

    Enum.into(attrs, %{
      signingKey: @signing_key,
      recoveryKey: @recovery_key,
      signer: @signer,
      handle: "#{username}.#{domain}",
      service: "https://pds.example.com",
      password: valid_did_password()
    })
  end

  def operation_fixture(attrs \\ @operation_attrs) do
    {:ok, %{operation: op}} =
      attrs
      |> valid_create_op_attributes()
      |> DidServer.Log.create_operation()

    op
  end

  @doc """
  Generate a did.
  """
  def key_fixture(attrs \\ @operation_attrs) do
    {:ok, %{key: key}} =
      attrs
      |> valid_create_op_attributes()
      |> DidServer.Log.create_operation()

    key
  end
end
