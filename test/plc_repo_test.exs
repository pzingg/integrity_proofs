defmodule IntegrityProofs.PlcRepoTest do
  use IntegrityProofs.DataCase

  alias IntegrityProofs.Math, as: IM
  alias IntegrityProofs.CID

  test "inserts a new create operation" do
    {signing_key, _} = IntegrityProofs.generate_key_pair(:did_key, :secp256k1)
    {recovery_key, _} = signer = IntegrityProofs.generate_key_pair(:did_key, :secp256k1)

    {op, did} =
      IntegrityProofs.Did.Plc.create_op(
        signing_key: signing_key,
        recovery_key: recovery_key,
        signer: signer,
        handle: "at://bob.bsky.social",
        service: "https://pds.example.com"
      )

    assert {:ok, %{did: %{did: did}, operation: %{did: did}, most_recent: nil}} =
             IntegrityProofs.Did.PlcLog.validate_and_add_op(did, op)
  end
end
