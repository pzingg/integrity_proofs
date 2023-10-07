defmodule CryptoUtils.DidTest do
  use ExUnit.Case

  test "decodes and uncompresses a p256 did:key" do
    assert %{jwt_alg: _jwt_alg, algo_key: algo_key} =
             CryptoUtils.Did.Methods.DidKey.parse!(
               "did:key:zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt"
             )

    assert {:ecdsa, [key_bytes, :secp256r1]} = algo_key
    assert byte_size(key_bytes) == 65
  end

  test "resolves a p256 did:key" do
    assert {:ok, {res_meta, doc, doc_meta}} =
             CryptoUtils.Did.Methods.DidKey.resolve(
               CryptoUtils.Did.Methods.DidKey,
               "did:key:zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt",
               nil
             )

    assert doc["verificationMethod"]["publicKeyJwk"]["kty"] == "EC"
    assert doc["verificationMethod"]["publicKeyJwk"]["crv"] == "P-256"
  end
end
