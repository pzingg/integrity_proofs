defmodule CryptoUtils.KeysTest do
  use ExUnit.Case

  alias CryptoUtils.{Curves, Keys}
  alias CryptoUtils.Keys.Keypair

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @private_key_bytes <<112, 38, 151, 226, 182, 82, 47, 205, 7, 158, 217, 27, 159, 218, 142, 29,
                       117, 44, 83, 74, 35, 121, 140, 91, 190, 215, 239, 144, 58, 42, 1, 200>>

  describe "pem decoding" do
    test "decodes an ed25519 public key" do
      {:ok, pem} = File.read("./test/support/fixtures/bob_example_ed25519.pub")

      {:ok, public_key, _priv} = Keys.decode_pem_ssh_file(pem, :public_key, :public_key)

      assert {{:ECPoint, pub}, {:namedCurve, _curve}} = public_key
      assert byte_size(pub) == 32
      assert pub == @public_key_bytes
    end

    test "decodes an ed25519 private key" do
      {:ok, pem} = File.read("./test/support/fixtures/bob_example_ed25519.priv")

      {:ok, _pub, private_key} = Keys.decode_pem_ssh_file(pem, :openssh_key_v1, :public_key)

      assert {:ECPrivateKey, 1, priv, {:namedCurve, _curve}, pub, _} = private_key
      assert byte_size(priv) == 32
      assert priv == @private_key_bytes
      assert byte_size(pub) == 32
      assert pub == @public_key_bytes
    end

    test "decodes a multibase encoded ed25519 public key" do
      {:ok, decoded} = Multibase.decode("z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP")
      assert byte_size(decoded) == 34
      assert <<237, 1>> <> _pub = decoded
    end

    test "decodes a pem-encoded p256 private key" do
      {:ok, pem} = File.read("./test/support/fixtures/p256.priv")

      {:ok, _pub, private_key} = Keys.decode_pem_ssh_file(pem, :openssh_key_v1, :public_key)

      assert {:ECPrivateKey, 1, priv, {:namedCurve, curve}, pub, _} = private_key
      assert byte_size(priv) == 32
      assert byte_size(pub) == 65
      assert curve == {1, 2, 840, 10045, 3, 1, 7}
    end

    test "decodes a pem-encoded secp256k1 private key" do
      {:ok, pem} = File.read("./test/support/fixtures/secp256k1.priv")

      {:ok, _pub, private_key} = Keys.decode_pem_ssh_file(pem, :openssh_key_v1, :public_key)

      assert {:ECPrivateKey, 1, priv, {:namedCurve, curve}, pub, _} = private_key
      assert byte_size(priv) == 32
      assert byte_size(pub) == 65
      assert curve == {1, 3, 132, 0, 10}
    end

    test "decodes and compresses a pem-encoded p256 public key" do
      {:ok, pem} = File.read("./test/support/fixtures/p256.pub")

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
      {:ok, pem} = File.read("./test/support/fixtures/p256.priv")

      assert {:ok, _,
              {:ECPrivateKey, 1, priv, {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}, pub, _}} =
               Keys.decode_pem_public_key(pem, :public_key)

      assert byte_size(priv) == 32
      assert byte_size(pub) == 65
    end
  end

  describe "jwk" do
    test "generates an :secp256k1 public key jwk" do
      assert {jwk_pub, jwk_priv, :jwk, :jwk} = Keys.generate_keypair(:secp256k1, :jwk)
      assert jwk_pub["kty"] == "EC"
      assert jwk_pub["crv"] == "secp256k1"
      assert jwk_pub["x"]
      assert jwk_pub["y"]

      assert jwk_priv["kty"] == "EC"
      assert jwk_priv["crv"] == "secp256k1"
      assert jwk_priv["d"]
      assert jwk_priv["x"]
      assert jwk_priv["y"]
    end

    test "generates an :p256 public key jwk" do
      assert {jwk_pub, jwk_priv, :jwk, :jwk} = Keys.generate_keypair(:p256, :jwk)
      assert jwk_pub["kty"] == "EC"
      assert jwk_pub["crv"] == "P-256"
      assert jwk_pub["x"]
      assert jwk_pub["y"]

      assert jwk_priv["kty"] == "EC"
      assert jwk_priv["crv"] == "P-256"
      assert jwk_priv["d"]
      assert jwk_priv["x"]
      assert jwk_priv["y"]
    end

    test "generates an :ed25519 public key jwk" do
      assert {jwk_pub, jwk_priv, :jwk, :jwk} = Keys.generate_keypair(:ed25519, :jwk)
      assert jwk_pub["kty"] == "OKP"
      assert jwk_pub["crv"] == "Ed25519"
      assert jwk_pub["x"]

      assert jwk_priv["kty"] == "OKP"
      assert jwk_priv["crv"] == "Ed25519"
      assert jwk_priv["d"]
      assert jwk_priv["x"]
    end
  end

  describe "pem encoding" do
    test "encodes an :secp256k1 private key" do
      assert {:ok, pem} =
               Keypair.generate(:secp256k1, :public_key)
               |> Keypair.encode_pem_private_key()

      assert String.starts_with?(pem, "-----BEGIN EC PRIVATE KEY-----")
    end

    test "encodes an :secp256k1 public key" do
      assert {:ok, pem} =
               Keypair.generate(:secp256k1, :public_key)
               |> Keypair.encode_pem_public_key()

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
