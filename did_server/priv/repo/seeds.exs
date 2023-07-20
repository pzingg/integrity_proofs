# Script for populating the database. You can run it as:
#
#     mix run priv/repo/seeds.exs
#
# Inside the script, you can read and write to any of your
# repositories directly:
#
#     DidServer.Repo.insert!(%DidServer.SomeSchema{})
#
# We recommend using the bang functions (`insert!`, `update!`
# and so on) as they will fail if something goes wrong.

if Mix.env() == :dev do
  {signing_key, _} = CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  {recovery_key, {algo, [priv, curve]}} = CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  signer = [recovery_key, to_string(algo), priv, to_string(curve)]

  {:ok, %{operation: %{did: did}}} =
    DidServer.Log.create_operation(%{
      # type: "create",
      signingKey: signing_key,
      recoveryKey: recovery_key,
      signer: signer,
      handle: "at://bob.bsky.social",
      service: "https://pds.example.com"
    })

  {:ok, bob_example_com} =
    DidServer.Accounts.register_user(%{
      email: "bob@example.com",
      username: "bob",
      domain: "example.com",
      password: "bluesky"
    })

    {:ok, bob_bsky_social} =
      DidServer.Accounts.register_user(%{
        email: "bob@bsky.social",
        username: "bob",
        domain: "bsky.social",
        password: "bluesky"
      })

  link = DidServer.Accounts.link_did_to_user(did, bob_example_com)
  link = DidServer.Accounts.link_did_to_user(did, bob_bsky_social)

  also_known_as = DidServer.Accounts.list_also_known_as_users(bob_example_com)
  IO.inspect(also_known_as)
end
