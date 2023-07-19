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

if false do
  {signing_key, _} = CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)
  {recovery_key, {algo, [priv, curve]}} = CryptoUtils.Keys.generate_keypair(:did_key, :secp256k1)

  signer = [recovery_key, to_string(algo), priv, to_string(curve)]

  {:ok, _} =
    DidServer.Log.create_operation(
      # type: "create",
      signingKey: signing_key,
      recoveryKey: recovery_key,
      signer: signer,
      handle: "at://bob.bsky.social",
      service: "https://pds.example.com"
    )
end
