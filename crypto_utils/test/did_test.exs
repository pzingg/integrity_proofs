defmodule CryptoUtils.DidTest do
  use ExUnit.Case

  test "decodes and uncompresses a p256 did:key" do
    assert %{jwt_alg: _jwt_alg, algo_key: algo_key} =
             CryptoUtils.Did.parse_did_key!(
               "did:key:zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt"
             )

    assert {:ecdsa, [key_bytes, :secp256r1]} = algo_key
    assert byte_size(key_bytes) == 65
  end
end
