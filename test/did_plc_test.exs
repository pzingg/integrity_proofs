defmodule IntegrityProofs.DidPlcTest do
  use ExUnit.Case

  def display_bytes(bin) do
    out =
      :binary.bin_to_list(bin)
      |> Enum.map(&Integer.to_string(&1))
      |> Enum.join(", ")

    "<<" <> out <> ">>"
  end

  test "decodes a p256 private key" do
    {:ok, pem} = File.read("./test/fixtures/p256.priv")
    {:ok, _pub, private_key} = IntegrityProofs.decode_pem(pem, :openssh_key_v1, :public_key)

    assert {:ECPrivateKey, 1, priv, {:namedCurve, curve}, pub} = private_key
    assert byte_size(priv) == 32
    assert byte_size(pub) == 65
    assert curve == {1, 2, 840, 10045, 3, 1, 7}
  end

  test "p256 compress public key" do
    {:ok, pem} = File.read("./test/fixtures/p256.pub")

    [entry = {:SubjectPublicKeyInfo, _encoded, :not_encrypted}] = :public_key.pem_decode(pem)

    assert {{:ECPoint, pub}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}} =
             :public_key.pem_entry_decode(entry)

    assert byte_size(pub) == 65
    assert {:ok, compressed} = IntegrityProofs.Did.Plc.compress_public_key_point(pub)
    assert <<mode::size(8), _rest::binary>> = compressed
    assert mode in [2, 3]

    assert {:ok, _uncompressed} =
             IntegrityProofs.Did.Plc.decompress_public_key_point(compressed, :p256)
  end

  test "p256 decode" do
    assert {:ok, d} = Multibase.decode("zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt")
    <<b0::size(8), b1::size(8)>> <> key_bytes = d
    assert b0 == 0x80
    assert b1 == 0x24
    assert byte_size(key_bytes) == 33
    <<mode::size(8), _rest::binary>> = key_bytes
    assert mode in [2, 3]
  end

  test "p256 did:key" do
    assert %{jwt_alg: _jwt_alg, algo_key: algo_key} =
             IntegrityProofs.Did.Plc.parse_did_key!(
               "did:key:zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt"
             )

    assert {:ecdsa, [key_bytes, :p256]} = algo_key
    assert byte_size(key_bytes) == 65
  end

  test "decodes a secp256k1 private key" do
    {:ok, pem} = File.read("./test/fixtures/secp256k1.priv")
    {:ok, _pub, private_key} = IntegrityProofs.decode_pem(pem, :openssh_key_v1, :public_key)

    assert {:ECPrivateKey, 1, priv, {:namedCurve, curve}, pub} = private_key
    assert byte_size(priv) == 32
    assert byte_size(pub) == 65
    assert curve == {1, 3, 132, 0, 10}
  end
end
