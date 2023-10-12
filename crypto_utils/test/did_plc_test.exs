defmodule DidPlcTest do
  use ExUnit.Case

  alias CryptoUtils.Did.Methods.DidPlc

  @sample_op %{
    "type" => "plc_operation",
    "alsoKnownAs" => ["at://bob.bsky.social"],
    "rotationKeys" => [
      "did:key:z7r8ooW3aEyHLkreRCpA5tCQ1GKrQUcGE4SUGjtrvWfwpgSHDymzi44ckDYPbF7fWsf3QzRVZ3Jny7fYne5GzX596Ev8K",
      "did:key:z7r8osqqQ7bvXXm1M3hFspUTZPouyRBzhJRr5x45cAkyEJJPTdZKvv6mwASGfhmYuR1qyngr5WhYf7AQ369pq1XHwZBT6"
    ],
    "verificationMethods" => %{
      "atproto" =>
        "did:key:z7r8osqqQ7bvXXm1M3hFspUTZPouyRBzhJRr5x45cAkyEJJPTdZKvv6mwASGfhmYuR1qyngr5WhYf7AQ369pq1XHwZBT6"
    },
    "services" => %{
      "atproto_pds" => %{
        "endpoint" => "https://pds.example.com",
        "type" => "AtprotoPersonalDataServer"
      }
    },
    "sig" =>
      "MEYCIQCaFkptyX4APu0bgro3GrG/vW/HXxdrfaFvgzxW3KUB5AIhAM1fhtJZ4c4VsLoOEtYwJzMItXRJW9tcNB/V9ZECdLEd",
    "prev" => nil
  }

  @sample_op_cid_str "bafyreidy2lsfczzflaw2w25"

  describe "did:plc" do
    test "creates a did" do
      assert {:ok, did} = DidPlc.did_for_create_op(@sample_op)
      assert String.starts_with?(did, "did:plc:")
      assert String.length(did) == 32
      assert did == "did:plc:pdjoiulhevmc3k3luwomyraz"
    end

    test "creates a CID from a PLC operation" do
      cid_str = DidPlc.cid_for_op(@sample_op)
      assert String.starts_with?(cid_str, "b")
      assert String.length(cid_str) == 24
      assert cid_str == @sample_op_cid_str
    end
  end
end
