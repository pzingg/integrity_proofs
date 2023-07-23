defmodule CryptoUtilsTest do
  use ExUnit.Case

  import CryptoUtils
  doctest CryptoUtils

  alias CryptoUtils.Math, as: CMath
  alias CryptoUtils.{Cid, Did}

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

  # From ipld-vectors.ts in atproto/common library
  @sample_cbor <<167, 100, 98, 111, 111, 108, 245, 100, 110, 117, 108, 108, 246, 101, 97, 114,
                 114, 97, 121, 131, 99, 97, 98, 99, 99, 100, 101, 102, 99, 103, 104, 105, 102,
                 111, 98, 106, 101, 99, 116, 164, 99, 97, 114, 114, 131, 99, 97, 98, 99, 99, 100,
                 101, 102, 99, 103, 104, 105, 100, 98, 111, 111, 108, 245, 102, 110, 117, 109, 98,
                 101, 114, 24, 123, 102, 115, 116, 114, 105, 110, 103, 99, 97, 98, 99, 102, 115,
                 116, 114, 105, 110, 103, 99, 97, 98, 99, 103, 105, 110, 116, 101, 103, 101, 114,
                 24, 123, 103, 117, 110, 105, 99, 111, 100, 101, 120, 47, 97, 126, 195, 182, 195,
                 177, 194, 169, 226, 189, 152, 226, 152, 142, 240, 147, 139, 147, 240, 159, 152,
                 128, 240, 159, 145, 168, 226, 128, 141, 240, 159, 145, 169, 226, 128, 141, 240,
                 159, 145, 167, 226, 128, 141, 240, 159, 145, 167>>

  @sample_cbor_cid_str "bafyreiclp443lavogvhj3d2ob2cxbfuscni2k5jk7bebjzg7khl3esabwq"

  describe "did:plc" do
    test "creates a did" do
      did = Did.did_for_create_op(@sample_op)
      assert String.starts_with?(did, "did:plc:")
      assert String.length(did) == 32
      assert did == "did:plc:pdjoiulhevmc3k3luwomyraz"
    end
  end

  describe "CID" do
    test "creates a CID from a CBOR" do
      cid = Cid.from_cbor(@sample_cbor)
      assert to_string(cid) == @sample_cbor_cid_str
    end

    test "decodes a CID" do
      cid = Cid.from_cbor(@sample_cbor)
      decoded_cid = Cid.decode!(@sample_cbor_cid_str)
      assert decoded_cid == cid
    end

    test "creates a CID from a PLC operation" do
      cid_str = Did.cid_for_op(@sample_op)
      assert String.starts_with?(cid_str, "b")
      assert String.length(cid_str) == 24
      assert cid_str == @sample_op_cid_str
    end
  end

  describe "math" do
    test "Tonelli-Shanks sqrt_mod algorithm" do
      p = 17
      a = 0
      b = 7
      x = 10
      y_squared = rem(CMath.mod_pow(x, 3, p) + a * x + b, p)
      assert y_squared == 4
      {:ok, y} = CMath.sqrt_mod(4, 17)
      assert y == 2
      assert CMath.mod_pow(2, 2, 17) == y_squared
      assert CMath.mod_pow(17 - 2, 2, 17) == y_squared
    end
  end
end
