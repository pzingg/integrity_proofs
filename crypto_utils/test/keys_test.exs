defmodule CryptoUtils.KeysTest do
  use ExUnit.Case

  alias CryptoUtils.{Curves, Keys}

  describe "pem decoding" do
    test "decodes a pem-encoded p256 private key" do
      {:ok, pem} = File.read("./test/fixtures/p256.priv")

      {:ok, _pub, private_key} = Keys.decode_pem_ssh_file(pem, :openssh_key_v1, :public_key)

      assert {:ECPrivateKey, 1, priv, {:namedCurve, curve}, pub} = private_key
      assert byte_size(priv) == 32
      assert byte_size(pub) == 65
      assert curve == {1, 2, 840, 10045, 3, 1, 7}
    end

    test "decodes a pem-encoded secp256k1 private key" do
      {:ok, pem} = File.read("./test/fixtures/secp256k1.priv")

      {:ok, _pub, private_key} = Keys.decode_pem_ssh_file(pem, :openssh_key_v1, :public_key)

      assert {:ECPrivateKey, 1, priv, {:namedCurve, curve}, pub} = private_key
      assert byte_size(priv) == 32
      assert byte_size(pub) == 65
      assert curve == {1, 3, 132, 0, 10}
    end

    test "decodes and compresses a pem-encoded p256 public key" do
      {:ok, pem} = File.read("./test/fixtures/p256.pub")

      assert {:ok, {{:ECPoint, pub}, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}}, _} =
               Keys.decode_pem_public_key(pem, :public_key)

      assert byte_size(pub) == 65
      assert {:ok, compressed} = Curves.compress_public_key_point(pub)
      assert <<mode::size(8), _rest::binary>> = compressed
      assert mode in [2, 3]

      assert {:ok, uncompressed} = Curves.decompress_public_key_point(compressed, :p256)

      assert uncompressed == pub
    end

    test "decodes and compresses a pem-encoded p256 private key" do
      {:ok, pem} = File.read("./test/fixtures/p256.priv")

      assert {:ok, _, {:ECPrivateKey, 1, priv, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}, pub}} =
               Keys.decode_pem_public_key(pem, :public_key)

      assert byte_size(priv) == 32
      assert byte_size(pub) == 65
    end
  end

  describe "pem encoding" do
    test "encodes an :secp256k1 private key" do
      assert {_pub, priv} = Keys.generate_keypair(:public_key, :secp256k1)
      assert {:ok, pem} = Keys.encode_pem_public_key(priv)
      assert String.starts_with?(pem, "-----BEGIN EC PRIVATE KEY-----")
    end

    test "encodes an :secp256k1 public key" do
      assert {pub, _priv} = Keys.generate_keypair(:public_key, :secp256k1)
      assert {:ok, pem} = Keys.encode_pem_public_key(pub)
      assert String.starts_with?(pem, "-----BEGIN PUBLIC KEY-----")
    end
  end

  describe "multibase decoding" do
    test "decodes the (compressed) Multibase value of a p256 public key" do
      assert {:ok, d} = Multibase.decode("zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt")
      <<b0::size(8), b1::size(8)>> <> key_bytes = d
      assert b0 == 0x80
      assert b1 == 0x24
      assert byte_size(key_bytes) == 33
      <<mode::size(8), _rest::binary>> = key_bytes
      assert mode in [2, 3]
    end
  end
end
