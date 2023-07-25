defmodule CryptoUtils.Keys do
  @moduledoc """
  Basic routines for generating and formatting public and private keys.
  """
  require Record

  alias CryptoUtils.Curves

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
  Generates a new random public-private key pair. `public_key_format` determines the
  format of the keys returned. See `make_public_key/3`
  and `make_private_key/3` for details on the return
  formats.
  """
  def generate_keypair(curve, public_key_format) do
    type =
      case curve do
        :ed25519 -> :eddsa
        :p256 -> :ecdh
        :secp256k1 -> :ecdh
        _ -> raise CryptoUtils.UnsupportedNamedCurveError, curve
      end

    private_key_format =
      case public_key_format do
        :did_key -> :crypto_algo_key
        _ -> public_key_format
      end

    {pub, priv} = :crypto.generate_key(type, curve)
    public_key = make_public_key(pub, curve, public_key_format)
    private_key = make_private_key({pub, priv}, curve, private_key_format)
    {public_key, private_key, public_key_format, private_key_format}
  end

  @doc """
  Extracts the public key from a "Multikey" verification method.

  See `make_public_key/3` for details on the formats for the
  returned key.
  """
  def extract_multikey(verification_method, fmt \\ :crypto_algo_key)

  def extract_multikey(
        %{"type" => "Multikey", "publicKeyMultibase" => multibase_value},
        fmt
      )
      when is_binary(multibase_value) do
    with {:ok, {pub, curve}} <- decode_multikey(multibase_value) do
      {:ok, make_public_key(pub, curve, fmt)}
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

  def make_public_key(pub, curve, :public_key) do
    {ec_point(point: pub), Curves.curve_params(curve)}
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
    ec_private_key(private_key: priv, public_key: pub, parameters: Curves.curve_params(:ed25519))
  end

  def make_private_key({pub, priv}, :p256, :public_key) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    ec_private_key(private_key: priv, public_key: pub, parameters: Curves.curve_params(:p256))
  end

  def make_private_key({pub, priv}, :secp256k1, :public_key) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    ec_private_key(
      private_key: priv,
      public_key: pub,
      parameters: Curves.curve_params(:secp256k1)
    )
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

  def encode_pem_public_key({{:ECPoint, _pub}, _curve_params} = public_key) do
    # openssl ecparam -genkey -name secp256r1 -noout -out <filename>
    entry = :public_key.pem_entry_encode(:SubjectPublicKeyInfo, public_key)
    pem = :public_key.pem_encode([entry])
    {:ok, pem}
  end

  def encode_pem_public_key(key) do
    {:error, "unkown key format #{inspect(key)}"}
  end

  def encode_pem_private_key({:ECPrivateKey, 1, priv, curve_params, pub}) do
    # openssl ecparam -genkey -name secp256r1 -noout -out <filename>
    private_key_asn1 = {:ECPrivateKey, 1, priv, curve_params, pub, :asn1_NOVALUE}
    entry = :public_key.pem_entry_encode(:ECPrivateKey, private_key_asn1)
    pem = :public_key.pem_encode([entry])
    {:ok, pem}
  end

  def encode_pem_private_key({did_key, {:ecdsa, [priv, curve]}}) do
    # openssl ecparam -genkey -name secp256r1 -noout -out <filename>
    %{algo_key: {:ecdsa, [pub, _curve]}} = CryptoUtils.Did.parse_did_key!(did_key)
    encode_pem_private_key({:ECPrivateKey, 1, priv, Curves.curve_params(curve), pub})
  end

  def encode_pem_private_key(key) do
    {:error, "unkown key format #{inspect(key)}"}
  end

  @doc """
  Parses keys in files produced by the `ssh-keygen` command.

  For example, create a public-private key pair with:

  ```sh
  ssh-keygen -t ed25519 -C "bob@example.com" -f example
  ```

  Then use this function to decode the public key:

  ```elixir
  File.read!("example.pub") |> decode_pem_ssh_file(:public_key)
  ```

  Or to decode the public key:

  ```elixir
  File.read!("example") |> decode_pem_ssh_file(:openssh_key_v1)
  ```

  See `make_public_key/3` and `make_private_key/3` for
  details on the formats for the returned keys.
  """
  def decode_pem_ssh_file(keys_pem, type \\ :openssh_key_v1, fmt \\ :crypto_algo_key)
      when is_binary(keys_pem) do
    case :ssh_file.decode(keys_pem, type) do
      decoded when is_list(decoded) ->
        decode_entries(decoded, fmt)

      {:error, reason} ->
        IO.puts("Could not decode #{type}: #{reason}")
        {:error, reason}

      other ->
        IO.puts("Unexpected result decoding #{type}: #{inspect(other)}")
    end
  end

  @doc """
  Parses public keys in files produced by the `openssl` command.
  """
  def decode_pem_public_key(keys_pem, fmt \\ :crypto_algo_key) when is_binary(keys_pem) do
    case :public_key.pem_decode(keys_pem) do
      entries when is_list(entries) ->
        Enum.map(entries, fn entry -> :public_key.pem_entry_decode(entry) end)
        |> decode_entries(fmt)

      {:error, reason} ->
        IO.puts("Could not decode: #{reason}")
        {:error, reason}

      other ->
        IO.puts("Unexpected result decoding: #{inspect(other)}")
    end
  end

  defp decode_entries(decoded, fmt) when is_list(decoded) do
    public_key =
      Enum.map(decoded, fn
        {{:ECPoint, _pub}, {:namedCurve, _}} = key ->
          key

        {{{:ECPoint, _pub}, {:namedCurve, _}} = key, attrs} when is_list(attrs) ->
          key

        _ ->
          nil
      end)
      |> Enum.filter(&is_tuple/1)
      |> case do
        [{{:ECPoint, pub}, {:namedCurve, curve_oid}} | _] ->
          curve = Curves.curve_from_oid(curve_oid)

          if is_nil(curve) do
            nil
          else
            make_public_key(pub, curve, fmt)
          end

        _ ->
          nil
      end

    private_key =
      Enum.map(decoded, fn
        {:ECPrivateKey, 1, _priv, {:namedCurve, _}, _pub, :asn1_NOVALUE} = key ->
          key

        {{:ECPrivateKey, 1, _priv, {:namedCurve, _}, _pub, :asn1_NOVALUE} = key, attrs}
        when is_list(attrs) ->
          key

        _ ->
          nil
      end)
      |> Enum.filter(&is_tuple/1)
      |> case do
        [{:ECPrivateKey, 1, priv, {:namedCurve, curve_oid}, pub, :asn1_NOVALUE} | _] ->
          curve = Curves.curve_from_oid(curve_oid)

          if is_nil(curve) do
            nil
          else
            make_private_key({pub, priv}, curve, fmt)
          end

        _ ->
          nil
      end

    {:ok, public_key, private_key}
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
