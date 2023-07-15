defmodule CryptoUtilsTest do
  use ExUnit.Case

  import CryptoUtils
  doctest CryptoUtils

  alias CryptoUtils.Math, as: CMath
  alias CryptoUtils.Cid

  describe "Cids" do
    test "CBOR and Cid encoding" do
      # From ipld-vectors.ts in atproto/common library
      cbor =
        <<167, 100, 98, 111, 111, 108, 245, 100, 110, 117, 108, 108, 246, 101, 97, 114, 114, 97,
          121, 131, 99, 97, 98, 99, 99, 100, 101, 102, 99, 103, 104, 105, 102, 111, 98, 106, 101,
          99, 116, 164, 99, 97, 114, 114, 131, 99, 97, 98, 99, 99, 100, 101, 102, 99, 103, 104,
          105, 100, 98, 111, 111, 108, 245, 102, 110, 117, 109, 98, 101, 114, 24, 123, 102, 115,
          116, 114, 105, 110, 103, 99, 97, 98, 99, 102, 115, 116, 114, 105, 110, 103, 99, 97, 98,
          99, 103, 105, 110, 116, 101, 103, 101, 114, 24, 123, 103, 117, 110, 105, 99, 111, 100,
          101, 120, 47, 97, 126, 195, 182, 195, 177, 194, 169, 226, 189, 152, 226, 152, 142, 240,
          147, 139, 147, 240, 159, 152, 128, 240, 159, 145, 168, 226, 128, 141, 240, 159, 145,
          169, 226, 128, 141, 240, 159, 145, 167, 226, 128, 141, 240, 159, 145, 167>>

      cid_str = "bafyreiclp443lavogvhj3d2ob2cxbfuscni2k5jk7bebjzg7khl3esabwq"

      cid = Cid.from_cbor(cbor)
      assert to_string(cid) == cid_str

      decoded_cid = Cid.decode!(cid_str)
      assert decoded_cid == cid
    end

    test "Cid encoding from a PLC operation" do
      op = %{
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

      cid_str =
        op
        |> Cid.from_data()
        |> Cid.encode!(truncate: 24)

      assert String.starts_with?(cid_str, "b")
      assert String.length(cid_str) == 24
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
