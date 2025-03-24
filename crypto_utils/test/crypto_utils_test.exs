defmodule CryptoUtilsTest do
  use ExUnit.Case

  import CryptoUtils
  doctest CryptoUtils

  alias CryptoUtils.Math, as: CMath
  alias CryptoUtils.Cid

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
