defmodule CryptoUtils.Keys do
  @moduledoc """
  Basic routines for generating and formatting public and private keys.
  """
  require Record

  alias CryptoUtils.{Curves, Did}

  defmodule InvalidPublicKeyError do
    defexception [:multibase, :reason]

    @impl true
    def message(%{multibase: multibase, reason: reason}) do
      "Invalid public Multikey #{multibase}: #{reason}"
    end
  end

  defmodule UnsupportedNamedCurveError do
    defexception [:type, :curve, :format]

    @impl true
    def message(%__MODULE__{type: type, curve: curve, format: format}) do
      "unsupported named curve #{curve} format #{format} for #{type} key"
    end
  end

  defmodule EllipticCurveError do
    defexception [:message]

    @impl true
    def exception(curve) do
      %__MODULE__{message: "point not on elliptic curve #{curve}"}
    end
  end

  @typedoc """
  Tuple for ASN.1 curve OID.
  """
  @type oid_tuple() ::
          {
            byte(),
            byte(),
            byte(),
            byte()
          }
          | {
              byte(),
              byte(),
              byte(),
              byte(),
              byte()
            }

  @doc """
  Erlang record for public key.
  Source: otp/lib/public_key/include/public_key.hrl

  -record('ECPoint', {
   point
  }).
  """
  @type ec_point_record() :: {
          :ECPoint,
          point: binary()
        }

  Record.defrecord(:ec_point, :ECPoint, point: "")

  @typedoc """
  Erlang record for private key.
  Source: otp/lib/public_key/asn1/ECPrivateKey.asn1:

  ECPrivateKey ::= SEQUENCE {
    version        INTEGER,
    privateKey     CurvePrivateKey,
    parameters [0] EcpkParameters OPTIONAL,
    publicKey  [1] CurvePublicKey OPTIONAL,
    -- Should be PKCS-8 Attributes but problem at the moment with PKCS-8 being part
    -- of PCKS-FRAME and PKIX1Algorithms88 is part of OTP-PUB-KEY. Procrastinate
    -- the solution as it mostly not used anyway
    attributes     ANY OPTIONAL
  }

  CurvePrivateKey ::= OCTET STRING
  CurvePublicKey ::= BIT STRING
  """
  @type ec_private_key_record() :: {
          :ECPrivateKey,
          version: integer(),
          private_key: binary(),
          parameters:
            {:ecParameters, tuple()}
            | {:namedCurve, oid_tuple()}
            | {:implicitlyCA, term()},
          public_key: bitstring(),
          attributes: term()
        }

  Record.defrecord(:ec_private_key, :ECPrivateKey,
    version: 1,
    private_key: "",
    parameters: nil,
    public_key: <<>>,
    attributes: :asn1_NOVALUE
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
  def generate_keypair(curve, public_key_format, private_key_format \\ nil) do
    priv_key_format =
      case {public_key_format, private_key_format} do
        {:multikey, nil} -> :crypto_algo_key
        {:did_key, nil} -> :crypto_algo_key
        {public_key_format, nil} -> public_key_format
        _ -> private_key_format
      end

    # This will also work?
    # priv = :public_key.generate_key(Curves.curve_params(curve))

    {pub, priv} = :crypto.generate_key(Curves.erlang_algo(curve), Curves.erlang_ec_curve(curve))
    public_key = make_public_key(pub, curve, public_key_format)
    private_key = make_private_key({pub, priv}, curve, priv_key_format)
    {public_key, private_key, public_key_format, priv_key_format}
  end

  @doc """
  Extracts the public key from a "Multikey" verification method.

  See `make_public_key/3` for details on the formats for the
  returned key.
  """
  def extract_multikey(verification_method, fmt)

  def extract_multikey(
        %{"type" => _type, "publicKeyMultibase" => multibase_value},
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
        raise InvalidPublicKeyError, multibase: multibase_value, reason: reason
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

  def make_public_key(pub, curve, :pem) do
    case {ec_point(point: pub), Curves.curve_params(curve)}
         |> encode_pem_public_key() do
      {:ok, pem} -> pem
      _ -> raise RuntimeError, "Could not generate pem"
    end
  end

  def make_public_key(pub, :ed25519, :jwk) do
    :jose_jwk_kty_okp_ed25519.to_map(pub, %{})
  end

  def make_public_key(pub, curve, :jwk) do
    ec_point_tuple = {ec_point(point: pub), Curves.curve_params(curve)}
    {kty_module, {key, fields}} = :jose_jwk_kty.from_key(ec_point_tuple)
    kty_module.to_map(key, fields)
  end

  def make_public_key(pub, :ed25519, :public_key_ed)
      when byte_size(pub) == 32 do
    {:ed_pub, :ed25519, pub}
  end

  def make_public_key(_, curve, format) do
    raise UnsupportedNamedCurveError, type: :public, curve: curve, format: format
  end

  @doc """
  Formats a public key parsed from a JWK map.
  """
  def public_key_from_jwk(%{"kty" => _} = jwk_map, fmt) do
    case from_jwk(jwk_map) do
      {:ok, {{pub, _priv}, curve}} -> {:ok, make_public_key(pub, curve, fmt)}
      {:ok, {pub, curve}} -> {:ok, make_public_key(pub, curve, fmt)}
      {:error, reason} -> {:error, reason}
    end
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
    ec_private_key(
      version: 1,
      private_key: priv,
      parameters: Curves.curve_params(:ed25519),
      public_key: pub
    )
  end

  def make_private_key({pub, priv}, :p256, :public_key) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    ec_private_key(
      version: 1,
      private_key: priv,
      parameters: Curves.curve_params(:p256),
      public_key: pub
    )
  end

  def make_private_key({pub, priv}, :secp256k1, :public_key) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    ec_private_key(
      version: 1,
      private_key: priv,
      parameters: Curves.curve_params(:secp256k1),
      public_key: pub
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
    {:ecdsa, [priv, :secp256r1]}
  end

  def make_private_key({pub, priv}, :secp256k1, :crypto_algo_key)
      when is_binary(pub) and is_binary(priv) do
    # pub is <<4>> <> <<x::32 bytes>> <> <<y::32 bytes>>
    # 4 means uncompressed format, x and y are curve coordinates
    # priv is 32 bytes
    {:ecdsa, [priv, :secp256k1]}
  end

  def make_private_key({pub, priv}, curve, :pem) do
    case ec_private_key(
           version: 1,
           private_key: priv,
           parameters: Curves.curve_params(curve),
           public_key: pub
         )
         |> encode_pem_private_key() do
      {:ok, pem} -> pem
      _ -> raise RuntimeError, "Could not generate pem"
    end
  end

  def make_private_key({pub, priv}, :ed25519, :jwk) do
    :jose_jwk_kty_okp_ed25519.to_map(<<priv::binary, pub::binary>>, %{})
  end

  def make_private_key({pub, priv}, curve, :jwk) do
    ec_private_key_tuple =
      ec_private_key(
        version: 1,
        private_key: priv,
        parameters: Curves.curve_params(curve),
        public_key: pub
      )

    {kty_module, {key, fields}} = :jose_jwk_kty.from_key(ec_private_key_tuple)
    kty_module.to_map(key, fields)
  end

  def make_private_key({pub, priv}, :ed25519, :public_key_ed)
      when byte_size(pub) == 32 and byte_size(priv) == 32 do
    {:ed_pri, :ed25519, pub, priv}
  end

  def make_private_key(_, curve, format) do
    raise UnsupportedNamedCurveError, type: :private, curve: curve, format: format
  end

  @doc """
  Formats a private key from a JWK map.
  """
  def private_key_from_jwk(%{"kty" => _} = jwk_map, fmt) do
    case from_jwk(jwk_map) do
      {:ok, {{pub, priv}, curve}} -> {:ok, make_private_key({pub, priv}, curve, fmt)}
      {:ok, _} -> {:error, "Not a private key"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp from_jwk(%{"kty" => _} = jwk_map) do
    case JOSE.JWK.from(jwk_map) |> JOSE.JWK.to_key() do
      {%{kty: :jose_jwk_kty_ec}, {:ECPrivateKey, _version, priv, {:namedCurve, oid}, pub, _attrs}} ->
        case CryptoUtils.Curves.curve_from_oid(oid) do
          nil ->
            {:error, "Named curve #{inspect(oid)} not supported"}

          curve ->
            {:ok, {{pub, priv}, curve}}
        end

      {%{kty: :jose_jwk_kty_ec}, {{:ECPoint, pub}, {:namedCurve, oid}}} ->
        case CryptoUtils.Curves.curve_from_oid(oid) do
          nil ->
            {:error, "Named curve #{inspect(oid)} not supported"}

          curve ->
            {:ok, {pub, curve}}
        end

      {%{kty: :jose_jwk_kty_ec}, _} = key ->
        {:error, "Key structure not supported #{inspect(key)}"}

      {%{kty: :jose_jwk_kty_okp_ed25519}, {_priv_key_type, {_pub_key_type, pub}, priv}} ->
        {:ok, {{pub, priv}, :ed25519}}

      {%{kty: :jose_jwk_kty_okp_ed25519}, {_pub_key_type, pub}} ->
        {:ok, {pub, :ed25519}}

      {%{kty: :jose_jwk_kty_okp_ed25519}, _} = key ->
        {:error, "Key structure not supported #{inspect(key)}"}

      key ->
        {:error, "Key type not supported #{inspect(key)}"}
    end
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

  def encode_pem_private_key({:ECPrivateKey, 1, _priv, _curve_params, _pub, _} = priv) do
    # openssl ecparam -genkey -name secp256r1 -noout -out <filename>
    entry = :public_key.pem_entry_encode(:ECPrivateKey, priv)
    pem = :public_key.pem_encode([entry])
    {:ok, pem}
  end

  def encode_pem_private_key({did_key, {:ecdsa, [priv, curve]}}) do
    # openssl ecparam -genkey -name secp256r1 -noout -out <filename>
    %{algo_key: {:ecdsa, [pub, _curve]}} = Did.parse_did!(did_key, expected_did_methods: [:key])

    ec_private_key(
      version: 1,
      private_key: priv,
      parameters: Curves.curve_params(curve),
      public_key: pub
    )
    |> encode_pem_private_key()
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
  def decode_pem_ssh_file(keys_pem, type \\ :openssh_key_v1, public_key_format \\ :did_key)
      when is_binary(keys_pem) do
    case :ssh_file.decode(keys_pem, type) do
      decoded when is_list(decoded) ->
        private_key_format =
          case public_key_format do
            :did_key -> :crypto_algo_key
            _ -> public_key_format
          end

        decode_entries(decoded, public_key_format, private_key_format)

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
  def decode_pem_public_key(keys_pem, public_key_format \\ :did_key)
      when is_binary(keys_pem) do
    case :public_key.pem_decode(keys_pem) do
      entries when is_list(entries) ->
        private_key_format =
          case public_key_format do
            :did_key -> :crypto_algo_key
            _ -> public_key_format
          end

        Enum.map(entries, fn entry -> :public_key.pem_entry_decode(entry) end)
        |> decode_entries(public_key_format, private_key_format)

      {:error, reason} ->
        IO.puts("Could not decode: #{reason}")
        {:error, reason}

      other ->
        IO.puts("Unexpected result decoding: #{inspect(other)}")
    end
  end

  defp decode_entries(decoded, public_key_format, private_key_format) when is_list(decoded) do
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
            make_public_key(pub, curve, public_key_format)
          end

        _ ->
          nil
      end

    {public_key, private_key} =
      Enum.map(decoded, fn
        {:ECPrivateKey, 1, _priv, {:namedCurve, _}, _pub, _attrs} = key ->
          key

        {{:ECPrivateKey, 1, _priv, {:namedCurve, _}, _pub, _attrs} = key, attrs}
        when is_list(attrs) ->
          key

        _ ->
          nil
      end)
      |> Enum.filter(&is_tuple/1)
      |> case do
        [{:ECPrivateKey, 1, priv, {:namedCurve, curve_oid}, pub, _attrs} | _] ->
          curve = Curves.curve_from_oid(curve_oid)

          if is_nil(curve) do
            {public_key, nil}
          else
            public_key = public_key || make_public_key(pub, curve, public_key_format)
            {public_key, make_private_key({pub, priv}, curve, private_key_format)}
          end

        _ ->
          {public_key, nil}
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

  defp curve_from_mapping(%Multicodec.MulticodecMapping{codec: codec, prefix: prefix}) do
    if codec in ["p256", "secp256k1"] do
      String.to_atom(codec)
    else
      raise ArgumentError, "codec '#{codec}', prefix #{inspect(prefix)} is not a recognized curve"
    end
  end
end
