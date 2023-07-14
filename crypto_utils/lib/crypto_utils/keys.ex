defmodule CryptoUtils.Keys do
  @moduledoc """
  Basic routines for generating and formatting public and private keys.
  """
  require Record

  @doc """
  Erlang record for public key.

  @type ec_point() :: {
    ECPoint,
    point: binary()
  }
  """
  Record.defrecord(:ec_point, :ECPoint, point: "")

  @doc """
  Erlang record for private key.

  @type oid_tuple() :: {
    a: byte(),
    b: byte(),
    c: byte(),
    d: byte()
  }

  @type ec_private_key() :: {
    ECPrivateKey,
    version: integer(),
   private_key: binary(),
    parameters: {:ecParameters, {ECParameters, ...} |
              {:namedCurve, oid_tuple()} |
              {:implicitlyCA, 'NULL'},
   public_key: bitstring()
  }
  """
  Record.defrecord(:ec_private_key, :ECPrivateKey,
    version: 1,
    private_key: "",
    parameters: nil,
    public_key: <<>>
  )

  # Named elliptic curves
  @id_ed25519 {1, 3, 101, 112}
  @id_p256 {1, 2, 840, 10045, 3, 1, 7}
  @id_secp256k1 {1, 3, 132, 0, 10}

  # Extra mappings not in Multicodec v0.0.2
  @p256_code 0x1200
  @p256_prefix <<0x80, 0x24>>
  @secp256k1_code 0xE7
  @secp256k1_prefix <<0xE7, 0x01>>
  @p256_mappings [
    %Multicodec.MulticodecMapping{code: @p256_code, codec: "p256", prefix: @p256_prefix},
    %Multicodec.MulticodecMapping{
      code: @secp256k1_code,
      codec: "secp256k1",
      prefix: @secp256k1_prefix
    }
  ]

  # Add these to our homegrown routine
  @multicodec_mappings @p256_mappings ++ Multicodec.mappings()

  @doc """
  Generates a new random public-private key pair. `fmt` determines the
  format of the keys returned. See `make_public_key/3`
  and `make_private_key/3` for details on the return
  formats.
  """
  def generate_key_pair(fmt, curve \\ :ed25519) do
    type =
      case curve do
        :ed25519 -> :eddsa
        :p256 -> :ecdh
        :secp256k1 -> :ecdh
        _ -> raise CryptoUtils.UnsupportedNamedCurveError, curve
      end

    priv_fmt =
      case fmt do
        :did_key -> :crypto_algo_key
        _ -> fmt
      end

    {pub, priv} = :crypto.generate_key(type, curve)
    {make_public_key(pub, curve, fmt), make_private_key({pub, priv}, curve, priv_fmt)}
  end

  @doc """
  Extracts the public key from a "Multikey" verification method.

  See `CryptoUtils.Keys.make_public_key/3` for details on the formats for the
  returned key.
  """
  def extract_multikey(verification_method, fmt \\ :crypto_algo_key)

  def extract_multikey(
        %{"type" => "Multikey", "publicKeyMultibase" => multibase_value},
        fmt
      )
      when is_binary(multibase_value) do
    with {:ok, {pub, curve}} <- decode_multikey(multibase_value) do
      {:ok, CryptoUtils.Keys.make_public_key(pub, curve, fmt)}
    end
  end

  def extract_multikey(_, _), do: {:error, "not a Multikey verification method"}

  @doc """
  Decodes the public key from a "Multikey" verification method's
  multibase value.

  Returns `{:ok, {raw_public_key_bytes, multicodec_mapping}}` on success.
  """
  def decode_multikey(multibase_value) do
    with {:ok, {public_key, :base58_btc}} <- Multibase.codec_decode(multibase_value),
         {:ok, {raw_public_key_bytes, mapping}} <- multicodec_mapping_decode(public_key),
         curve <- curve_from_mapping(mapping) do
      {:ok, {raw_public_key_bytes, curve}}
    end
  end

  @doc """
  Decodes the public key from a "Multikey" verification method's
  multibase value.

  Returns `{raw_public_key_bytes, codec, multicodec_mapping}` on success.
  Raises `InvalidPublicKeyError` on failure.
  """
  def decode_multikey!(multibase_value) do
    case decode_multikey(multibase_value) do
      {:ok, {_key_bytes, _curve} = tuple} ->
        tuple

      {:error, reason} ->
        raise CryptoUtils.InvalidPublicKeyError, multibase: multibase_value, reason: reason
    end
  end

  @doc """
  Returns a public key, from supplied data. `fmt` determines the
  format of the key returned.

  * `:public_key` returns a tuple `{{:ECPoint, pub}, {:namedCurve, {1, 3, 101, 112}}`.
  * `:public_key_ed` returns a tuple `{:ed_pub, :ed25519, pub}`.
  * `:crypto_algo_key` returns a tuple `{:eddsa, [pub, :ed25519]}`.
  * `:multikey` returns a btc58-encoded binary starting with "z6".
  * `:did_key` returns a binary starting with "did:key:".
  """
  def make_public_key(pub, curve, :did_key) do
    multikey = make_public_key(pub, curve, :multikey)
    "did:key:" <> multikey
  end

  def make_public_key(pub, :ed25519, :public_key)
      when byte_size(pub) == 32 do
    {ec_point(point: pub), {:namedCurve, @id_ed25519}}
  end

  def make_public_key(pub, :p256, :public_key) do
    {ec_point(point: pub), {:namedCurve, @id_p256}}
  end

  def make_public_key(pub, :secp256k1, :public_key) do
    {ec_point(point: pub), {:namedCurve, @id_secp256k1}}
  end

  def make_public_key(pub, :ed25519, :crypto_algo_key)
      when byte_size(pub) == 32 do
    {:eddsa, [pub, :ed25519]}
  end

  def make_public_key(pub, :p256, :crypto_algo_key) do
    {:ecdsa, [pub, :p256]}
  end

  def make_public_key(pub, :secp256k1, :crypto_algo_key) do
    {:ecdsa, [pub, :secp256k1]}
  end

  def make_public_key(pub, :ed25519, :multikey)
      when byte_size(pub) == 32 do
    pub
    |> Multicodec.encode!("ed25519-pub")
    |> Multibase.encode!(:base58_btc)
  end

  def make_public_key(pub, :p256, :multikey)
      when byte_size(pub) == 33 or byte_size(pub) == 65 do
    # Multicodec.encode!("p256")
    <<@p256_prefix::binary, pub::binary>>
    |> Multibase.encode!(:base58_btc)
  end

  def make_public_key(pub, :secp256k1, :multikey)
      when byte_size(pub) == 33 or byte_size(pub) == 65 do
    # Multicodec.encode!("secp256k1")
    <<@secp256k1_prefix::binary, pub::binary>>
    |> Multibase.encode!(:base58_btc)
  end

  def make_public_key(pub, :ed25519, :public_key_ed)
      when byte_size(pub) == 32 do
    {:ed_pub, :ed25519, pub}
  end

  def make_public_key(_, curve, _) do
    raise CryptoUtils.UnsupportedNamedCurveError, curve
  end

  @doc """
  Returns a private key, from supplied data. `fmt` determines the
  format of the key returned.

  * `:public_key` returns a tuple `{:ECPrivateKey, 1, priv, {:namedCurve, {1, 3, 101, 112}}, pub}`.
  * `:public_key_ed` returns a tuple `{:ed_pri, :ed25519, pub, priv}`.
  * `:crypto_algo_key` returns a tuple `{:eddsa, [priv, :ed25519]}`.
  """
  def make_private_key({pub, priv}, :ed25519, :public_key)
      when byte_size(pub) == 32 and byte_size(priv) == 32 do
    ec_private_key(private_key: priv, public_key: pub, parameters: {:namedCurve, @id_ed25519})
  end

  def make_private_key({pub, priv}, :p256, :public_key) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    ec_private_key(private_key: priv, public_key: pub, parameters: {:namedCurve, @id_p256})
  end

  def make_private_key({pub, priv}, :secp256k1, :public_key) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    ec_private_key(private_key: priv, public_key: pub, parameters: {:namedCurve, @id_secp256k1})
  end

  def make_private_key({pub, priv}, :ed25519, :crypto_algo_key)
      when byte_size(pub) == 32 and byte_size(priv) == 32 do
    {:eddsa, [priv, :ed25519]}
  end

  def make_private_key({pub, priv}, :p256, :crypto_algo_key)
      when is_binary(pub) and is_binary(priv) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    {:ecdsa, [priv, :p256]}
  end

  def make_private_key({pub, priv}, :secp256k1, :crypto_algo_key)
      when is_binary(pub) and is_binary(priv) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    {:ecdsa, [priv, :secp256k1]}
  end

  def make_private_key({pub, priv}, :ed25519, :public_key_ed)
      when byte_size(pub) == 32 and byte_size(priv) == 32 do
    {:ed_pri, :ed25519, pub, priv}
  end

  def make_private_key(_, curve, _) do
    raise CryptoUtils.UnsupportedNamedCurveError, curve
  end

  defp multicodec_mapping_decode(prefixed_bytes) do
    @multicodec_mappings
    |> Enum.reduce_while({:error, "not found"}, fn %{prefix: prefix} = mapping, acc ->
      plen = byte_size(prefix)

      case prefixed_bytes do
        <<^prefix::binary-size(plen), key_bytes::binary>> -> {:halt, {:ok, {key_bytes, mapping}}}
        _ -> {:cont, acc}
      end
    end)
  end

  defp curve_from_mapping(%Multicodec.MulticodecMapping{codec: "ed25519-pub"}) do
    :ed25519
  end

  defp curve_from_mapping(%Multicodec.MulticodecMapping{codec: codec}) do
    String.to_existing_atom(codec)
  end
end
