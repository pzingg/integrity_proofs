defmodule CryptoUtils.DependencyTest do
  use ExUnit.Case

  require Multibase

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @private_key_bytes <<112, 38, 151, 226, 182, 82, 47, 205, 7, 158, 217, 27, 159, 218, 142, 29,
                       117, 44, 83, 74, 35, 121, 140, 91, 190, 215, 239, 144, 58, 42, 1, 200>>

  @test_message "test message"

  @test_message_signature <<127, 250, 49, 201, 232, 75, 72, 204, 28, 181, 33, 161, 44, 36, 147,
                            22, 194, 35, 49, 133, 41, 105, 233, 59, 138, 215, 250, 149, 204, 132,
                            58, 38, 193, 27, 87, 172, 29, 26, 4, 211, 194, 107, 207, 11, 67, 134,
                            226, 91, 244, 67, 28, 143, 74, 253, 219, 146, 100, 134, 154, 154, 64,
                            247, 227, 11>>

  describe "Erlang support" do
    test "Erlang :crypto app supports eddsa and ed25519" do
      crypto_supports = :crypto.supports()
      public_keys = Keyword.fetch!(crypto_supports, :public_keys)
      assert :eddsa in public_keys
      curves = Keyword.fetch!(crypto_supports, :curves)
      assert :ed25519 in curves
    end

    test "Erlang :crypto.generate_key/2 creates an ed25519 key pair" do
      {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
      assert byte_size(pub) == 32
      assert byte_size(priv) == 32
    end

    test "Erlang :public_key.format_sign_key/1 supports eddsa and ed25519" do
      private_key =
        CryptoUtils.Keys.make_private_key(
          {@public_key_bytes, @private_key_bytes},
          :ed25519,
          :public_key
        )

      fmt = :dbg_public_key.format_sign_key(private_key)
      assert fmt == {:eddsa, [@private_key_bytes, :ed25519]}
    end

    test "Erlang :crypto.sign/5 supports eddsa and ed25519 public key" do
      private_key =
        CryptoUtils.Keys.make_private_key(
          {@public_key_bytes, @private_key_bytes},
          :ed25519,
          :public_key
        )

      {algorithm, crypto_key} = :dbg_public_key.format_sign_key(private_key)
      signature = :crypto.sign(algorithm, :none, @test_message, crypto_key, [])
      assert signature == @test_message_signature
    end

    test "Erlang :public_key.format_verify_key/1 supports eddsa and ed25519" do
      public_key = CryptoUtils.Keys.make_public_key(@public_key_bytes, :ed25519, :public_key)
      fmt = :dbg_public_key.format_verify_key(public_key)
      assert fmt == {:eddsa, [@public_key_bytes, :ed25519]}
    end

    test "Erlang :public_key.verify/6 supports eddsa and ed25519" do
      public_key = CryptoUtils.Keys.make_public_key(@public_key_bytes, :ed25519, :public_key)
      {algorithm, crypto_key} = :dbg_public_key.format_verify_key(public_key)

      assert :crypto.verify(
               algorithm,
               :none,
               @test_message,
               @test_message_signature,
               crypto_key,
               []
             )
    end
  end

  describe "Multibase and Multicodec support" do
    test "Multicodec supports ed25119-pub" do
      assert "ed25519-pub" in Multicodec.codecs()

      %{prefix: prefix, code: code} =
        Multicodec.mappings()
        |> Enum.filter(fn %{codec: codec} -> codec == "ed25519-pub" end)
        |> hd()

      assert code == 237
      # "\xED\x01" == << 237, 1 >>
      assert prefix == <<237, 1>>
    end

    test "Multibase supports btc58" do
      assert :base58_btc in Multibase.encodings()
    end
  end
end
