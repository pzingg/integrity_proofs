defmodule IntegrityProofs.DidPlcTest do
  use ExUnit.Case

  alias IntegrityProofs.Math, as: IM
  alias IntegrityProofs.CID

  test "CBOR and CID encoding" do
    # From ipld-vectors.ts in atproto/common library
    cbor =
      <<167, 100, 98, 111, 111, 108, 245, 100, 110, 117, 108, 108, 246, 101, 97, 114, 114, 97,
        121, 131, 99, 97, 98, 99, 99, 100, 101, 102, 99, 103, 104, 105, 102, 111, 98, 106, 101,
        99, 116, 164, 99, 97, 114, 114, 131, 99, 97, 98, 99, 99, 100, 101, 102, 99, 103, 104, 105,
        100, 98, 111, 111, 108, 245, 102, 110, 117, 109, 98, 101, 114, 24, 123, 102, 115, 116,
        114, 105, 110, 103, 99, 97, 98, 99, 102, 115, 116, 114, 105, 110, 103, 99, 97, 98, 99,
        103, 105, 110, 116, 101, 103, 101, 114, 24, 123, 103, 117, 110, 105, 99, 111, 100, 101,
        120, 47, 97, 126, 195, 182, 195, 177, 194, 169, 226, 189, 152, 226, 152, 142, 240, 147,
        139, 147, 240, 159, 152, 128, 240, 159, 145, 168, 226, 128, 141, 240, 159, 145, 169, 226,
        128, 141, 240, 159, 145, 167, 226, 128, 141, 240, 159, 145, 167>>

    cid_str = "bafyreiclp443lavogvhj3d2ob2cxbfuscni2k5jk7bebjzg7khl3esabwq"

    cid = CID.from_cbor(cbor)
    assert to_string(cid) == cid_str

    decoded_cid = CID.decode!(cid_str)
    assert decoded_cid == cid
  end

  test "tonelli-shanks sqrt_mod" do
    p = 17
    a = 0
    b = 7
    x = 10
    y_squared = rem(IM.mod_pow(x, 3, p) + a * x + b, p)
    assert y_squared == 4
    {:ok, y} = IM.sqrt_mod(4, 17)
    assert y == 2
    assert IM.mod_pow(2, 2, 17) == y_squared
    assert IM.mod_pow(17 - 2, 2, 17) == y_squared
  end

  test "decodes a pem-encoded p256 private key" do
    {:ok, pem} = File.read("./test/fixtures/p256.priv")

    {:ok, _pub, private_key} =
      IntegrityProofs.decode_pem_ssh_file(pem, :openssh_key_v1, :public_key)

    assert {:ECPrivateKey, 1, priv, {:namedCurve, curve}, pub} = private_key
    assert byte_size(priv) == 32
    assert byte_size(pub) == 65
    assert curve == {1, 2, 840, 10045, 3, 1, 7}
  end

  test "decodes a pem-encoded secp256k1 private key" do
    {:ok, pem} = File.read("./test/fixtures/secp256k1.priv")

    {:ok, _pub, private_key} =
      IntegrityProofs.decode_pem_ssh_file(pem, :openssh_key_v1, :public_key)

    assert {:ECPrivateKey, 1, priv, {:namedCurve, curve}, pub} = private_key
    assert byte_size(priv) == 32
    assert byte_size(pub) == 65
    assert curve == {1, 3, 132, 0, 10}
  end

  test "decodes and compresses a pem-encoded p256 public key" do
    {:ok, pem} = File.read("./test/fixtures/p256.pub")

    assert {:ok, {{:ECPoint, pub}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}} =
             IntegrityProofs.decode_pem_public_key(pem, :public_key)

    assert byte_size(pub) == 65
    assert {:ok, compressed} = IntegrityProofs.Did.Plc.compress_public_key_point(pub)
    assert <<mode::size(8), _rest::binary>> = compressed
    assert mode in [2, 3]

    assert {:ok, uncompressed} =
             IntegrityProofs.Did.Plc.decompress_public_key_point(compressed, :p256)

    assert uncompressed == pub
  end

  test "decodes the (compressed) Multibase value of a p256 public key" do
    assert {:ok, d} = Multibase.decode("zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt")
    <<b0::size(8), b1::size(8)>> <> key_bytes = d
    assert b0 == 0x80
    assert b1 == 0x24
    assert byte_size(key_bytes) == 33
    <<mode::size(8), _rest::binary>> = key_bytes
    assert mode in [2, 3]
  end

  test "decodes and uncompresses a p256 did:key" do
    assert %{jwt_alg: _jwt_alg, algo_key: algo_key} =
             IntegrityProofs.Did.Plc.parse_did_key!(
               "did:key:zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt"
             )

    assert {:ecdsa, [key_bytes, :p256]} = algo_key
    assert byte_size(key_bytes) == 65
  end

  test "encodes a plc operation with CBOR" do
    {signing_key, _} = IntegrityProofs.generate_key_pair(:did_key, :secp256k1)
    {recovery_key, _} = IntegrityProofs.generate_key_pair(:did_key, :secp256k1)

    {_normalized_op, did} =
      IntegrityProofs.Did.Plc.create_op(
        signing_key: signing_key,
        recovery_key: recovery_key,
        handle: "at://user1@example.com",
        service: "https://example.com",
        signer: recovery_key
      )

    assert "did:plc:" <> <<_id::binary-size(24)>> = did
  end

  test "makes a dag-cbor CID, truncated to 24 characters" do
    {signing_key, _} = IntegrityProofs.generate_key_pair(:did_key, :secp256k1)
    {recovery_key, _} = IntegrityProofs.generate_key_pair(:did_key, :secp256k1)

    assert String.starts_with?(signing_key, "did:key:z7")
    assert String.starts_with?(recovery_key, "did:key:z7")

    {normalized_op, _did} =
      IntegrityProofs.Did.Plc.create_op(
        signing_key: signing_key,
        recovery_key: recovery_key,
        handle: "at://bob.bsky.social",
        service: "https://pds.example.com",
        signer: recovery_key
      )

    cid_str =
      normalized_op
      |> CID.from_data()
      |> CID.encode!(truncate: 24)

    assert String.starts_with?(cid_str, "b")
    assert String.length(cid_str) == 24
  end
end
