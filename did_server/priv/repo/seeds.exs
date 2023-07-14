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

{signing_key, _} = CryptoUtils.Keys.generate_key_pair(:did_key, :secp256k1)
{recovery_key, _} = signer = CryptoUtils.Keys.generate_key_pair(:did_key, :secp256k1)

{op, did} =
  DidServer.create_op(
    signing_key: signing_key,
    recovery_key: recovery_key,
    signer: signer,
    handle: "at://bob.bsky.social",
    service: "https://pds.example.com"
  )

{:ok, _} = DidServer.Log.validate_and_add_op(did, op)
