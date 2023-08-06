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
  signing_key =
    CryptoUtils.Keys.Keypair.generate(:secp256k1, :did_key) |> CryptoUtils.Keys.Keypair.did()

  recovery_keypair = CryptoUtils.Keys.Keypair.generate(:secp256k1, :did_key)
  recovery_key = CryptoUtils.Keys.Keypair.did(recovery_keypair)
  signer = CryptoUtils.Keys.Keypair.to_json(recovery_keypair)

  {:ok, bob_example_com} =
    DidServer.Accounts.register_user(%{
      email: "bob@example.com",
      username: "bob",
      domain: "example.com",
      password: "bluesky",
      signer: signer,
      signing_key: signing_key,
      recovery_key: recovery_key
    })

  %{did: did} = DidServer.Identities.get_user_did(bob_example_com)

  {:ok, _bob_bsky_social} =
    DidServer.Accounts.register_user(%{
      email: "bob@bsky.social",
      username: "bob",
      domain: "bsky.social",
      did: did
    })

  also_known_as = DidServer.Accounts.list_also_known_as_users(bob_example_com)
  IO.puts("#{Enum.count(also_known_as)} user(s) in did #{did}")
end
