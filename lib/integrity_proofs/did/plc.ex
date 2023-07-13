defmodule IntegrityProofs.Did.Plc do
  @moduledoc """
  Elixir implementation of Bluesky's did:plc method.

  See https://github.com/bluesky-social/did-method-plc
  """

  require Integer

  alias IntegrityProofs.Math, as: IM
  alias IntegrityProofs.CID

  defmodule Block do
    defstruct [:cid, :bytes, :value, :codec, :hasher]
  end

  defmodule CreateOpV1 do
    defstruct [:signing_key, :recovery_key, :handle, :service, :prev, :sig, type: "create"]
  end

  defmodule InvalidSignatureError do
    defexception [:message]

    @impl true
    def exception(_op) do
      %__MODULE__{message: "invalid signature"}
    end
  end

  defmodule PrevMismatchError do
    defexception [:message]
  end

  defmodule MisorderedOperationError do
    defexception []

    @impl true
    def message(_) do
      "misordered plc operation"
    end
  end

  defmodule LateRecoveryError do
    defexception [:message]

    @impl true
    def exception(lapsed) do
      %__MODULE__{message: "72 hour recovery period exceeded: #{lapsed} seconds"}
    end
  end

  defmodule GenesisHashError do
    defexception [:message]

    @impl true
    def exception(expected_did) do
      %__MODULE__{message: "expected did #{expected_did} for genesis operation"}
    end
  end

  defmodule ImproperOperationError do
    defexception [:op, :message]

    @impl true
    def message(%{op: op, message: message}) do
      "#{message}, op: #{inspect(op)}"
    end
  end

  defmodule UnsupportedKeyError do
    defexception [:message]

    @impl true
    def exception(key) do
      %__MODULE__{message: "Unsupported key #{key}"}
    end
  end

  @p256_code 0x1200
  @p256_prefix <<0x80, 0x24>>
  @p256_jwt_alg "ES256"
  @p256_params {"p256",
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
                |> IM.parse_hex(),
                "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
                |> IM.parse_hex(),
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
                |> IM.parse_hex()}

  @secp256k1_code 0xE7
  @secp256k1_prefix <<0xE7, 0x01>>
  @secp256k1_jwt_alg "ES256K"
  @secp256k1_params {"secp256k1",
                     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
                     |> IM.parse_hex(), 0, 7}

  @context ["https://www.w3.org/ns/did/v1"]

  def format_did_doc(%{did: did, also_known_as: also_known_as} = data) when is_binary(did) do
    {context, verification_methods} =
      Map.get(data, :verification_methods, %{})
      |> Enum.reduce(
        {@context, []},
        fn {key_id, key}, {ctx, vms} ->
          %{context: context, type: type, public_key_multibase: public_key_multibase} =
            format_key_and_context(key)

          ctx =
            if context in [ctx] do
              ctx
            else
              [context | ctx]
            end

          vms = [
            %{
              "id" => key_id,
              "type" => type,
              "controller" => did,
              "publicKeyMultibase" => public_key_multibase
            }
            | vms
          ]

          {ctx, vms}
        end
      )

    services =
      Map.get(data, :services, %{})
      |> Enum.map(fn {service_id, %{type: type, endpoint: endpoint}} ->
        %{"id" => service_id, "type" => type, "serviceEndpoint" => endpoint}
      end)

    %{
      "@context" => Enum.reverse(context),
      "id" => did,
      "alsoKnownAs" => also_known_as,
      "verificationMethod" => verification_methods,
      "service" => services
    }
  end

  def format_key_and_context(did) do
    %{jwt_alg: jwt_alg, key_bytes: key_bytes} = parse_did_key!(did)

    case jwt_alg do
      @p256_jwt_alg ->
        %{
          context: "https://w3id.org/security/suites/ecdsa-2019/v1",
          type: "EcdsaSecp256r1VerificationKey2019",
          public_key_multibase: Multibase.encode!(key_bytes, :base58_btc)
        }

      @secp256k1_jwt_alg ->
        %{
          context: "https://w3id.org/security/suites/secp256k1-2019/v1",
          type: "EcdsaSecp256k1VerificationKey2019",
          public_key_multibase: Multibase.encode!(key_bytes, :base58_btc)
        }
    end
  end

  def parse_did_key!(did) do
    %{multibase_value: multibase_value} =
      IntegrityProofs.Did.parse_did!(did, expected_did_method: "key")

    prefixed_bytes = Multibase.decode!(multibase_value)
    <<b0::size(8), b1::size(8)>> <> key_bytes = prefixed_bytes
    prefix = <<b0::size(8), b1::size(8)>>

    case prefix do
      @p256_prefix ->
        case decompress_public_key_point(key_bytes, :p256) do
          {:ok, uncompressed} ->
            %{
              jwt_alg: @p256_jwt_alg,
              key_bytes: prefixed_bytes,
              algo_key: {:ecdsa, [uncompressed, :p256]}
            }

          _ ->
            raise IntegrityProofs.Did.EllipticCurveError, "p256"
        end

      @secp256k1_prefix ->
        case decompress_public_key_point(key_bytes, :secp256k1) do
          {:ok, uncompressed} ->
            %{
              jwt_alg: @secp256k1_jwt_alg,
              key_bytes: prefixed_bytes,
              algo_key: {:ecdsa, [uncompressed, :secp256k1]}
            }

          _ ->
            raise IntegrityProofs.Did.EllipticCurveError, "secp256k1"
        end

      _ ->
        raise IntegrityProofs.Did.UnsupportedPublicKeyCodecError, prefix
    end
  end

  # Operations

  def create_op(params) do
    op = struct(CreateOpV1, params) |> normalize_op()
    did = did_for_create_op(op)
    {op, did}
  end

  def did_for_create_op(%{"prev" => nil} = normalized_op) do
    cbor = CBOR.encode(normalized_op)
    # <<166, 107, 97, 108, 115, 111, 75, 110, 111, 119, 110, 65, 115, 129, 118, 97
    hash_of_genesis = :crypto.hash(:sha256, cbor)

    truncated_id =
      hash_of_genesis |> Base.encode32(case: :lower, padding: false) |> String.slice(0, 24)

    "did:plc:#{truncated_id}"
  end

  def normalize_op(%CreateOpV1{sig: sig} = op) do
    normalized_op = %{
      "type" => "plc_operation",
      "verificationMethods" => %{
        "atproto" => op.signing_key
      },
      "rotationKeys" => [op.recovery_key, op.signing_key],
      "alsoKnownAs" => [ensure_atproto_prefix(op.handle)],
      "services" => %{
        "atproto_pds" => %{
          "type" => "AtprotoPersonalDataServer",
          "endpoint" => ensure_http_prefix(op.service)
        }
      },
      "prev" => op.prev
    }

    if is_nil(sig) do
      normalized_op
    else
      Map.put(normalized_op, "sig", sig)
    end
  end

  def normalize_op(%{"type" => _type} = op), do: op

  def make_cid(normalized_op) do
    normalized_op
    |> CID.from_data()
    |> CID.encode!(truncate: 24)
  end

  def ensure_http_prefix(str) do
    if String.starts_with?(str, "http://") || String.starts_with?(str, "https://") do
      str
    else
      "https://" <> str
    end
  end

  def ensure_atproto_prefix(str) do
    if String.starts_with?(str, "at://") do
      str
    else
      "at://" <>
        (str
         |> String.replace_leading("http://", "")
         |> String.replace_leading("https://", ""))
    end
  end

  def assure_valid_creation_op(did, %{"type" => type} = op) do
    if type == "plc_tombstone" do
      raise MisorderedOperationError
    end

    assure_valid_op(op)
    assure_valid_sig(op.rotation_keys, op)
    expected_did = did_for_create_op(op)

    if did != expected_did do
      raise GenesisHashError, expected_did
    end

    if !is_nil(op.prev) do
      raise ImproperOperationError, op: op, message: "expected null prev on create"
    end

    op
  end

  def assure_valid_op(%{"type" => "plc_tombstone"} = op), do: op

  def assure_valid_op(%{"rotationKeys" => rotation_keys, "verificationMethods" => vms} = op) do
    # ensure we support the op's keys
    keys = Map.values(vms) ++ rotation_keys

    Enum.each(keys, fn key ->
      try do
        parse_did_key!(key)
      rescue
        _ -> raise UnsupportedKeyError, key
      end
    end)

    if Enum.count(rotation_keys) > 5 do
      raise ImproperOperationError, op: op, message: "too many rotation keys"
    end

    if Enum.count(rotation_keys) < 1 do
      raise ImproperOperationError, op: op, message: "need at least one rotation key"
    end

    op
  end

  def assure_valid_sig(allowed_did_keys, %{"sig" => sig} = op) when is_binary(sig) do
    with {:ok, sig_bytes} <- Base.decode64(sig),
         data_bytes <- Map.delete(op, "sig") |> normalize_op() |> CBOR.encode() do
      valid =
        Enum.find(allowed_did_keys, fn did_key ->
          verify_signature(did_key, data_bytes, sig_bytes)
        end)

      if is_nil(valid) do
        :error
      else
        valid
      end
    else
      _ -> raise InvalidSignatureError, op
    end
  end

  def verify_signature(did_key, data_bytes, sig_bytes) do
    # TODO: implement for p256 and secp256k1, according to did
    false
  end

  def format_service({service_id, %{type: type, endpoint: endpoint}}) do
    {service_id, %{"type" => type, "endpoint" => endpoint}}
  end

  def compress_public_key_point(<<mode::size(8), x_coord::binary-size(32), y_coord::binary>>) do
    test =
      case {mode, byte_size(y_coord)} do
        {4, 32} -> :ok
        {_, 32} -> {:error, "invalid mode #{mode}"}
        {_, n} -> {:error, "invalid size for uncompressed key #{n + 33}"}
      end

    with :ok <- test do
      if :binary.decode_unsigned(y_coord, :big) |> Integer.is_even() do
        {:ok, <<2>> <> x_coord}
      else
        {:ok, <<3>> <> x_coord}
      end
    end
  end

  def decompress_public_key_point(point, curve_oid) when is_tuple(curve_oid) do
    curve = IntegrityProofs.curve_from_oid(curve_oid)

    if curve in [:p256, :secp256k1] do
      decompress_public_key_point(point, curve)
    else
      {:error, "invalid curve OID #{inspect(curve_oid)}"}
    end
  end

  def decompress_public_key_point(point, :p256) do
    decompress_curve_point(point, @p256_params)
  end

  def decompress_public_key_point(point, :secp256k1) do
    decompress_curve_point(point, @secp256k1_params)
  end

  def decompress_curve_point(<<4, _coords::binary>> = key_bytes, _)
      when byte_size(key_bytes) == 65,
      do: key_bytes

  def decompress_curve_point(<<mode::size(8), x_coord::binary>>, {_name, p, a, b}) do
    test =
      case {mode, byte_size(x_coord)} do
        {2, 32} -> {:ok, false}
        {3, 32} -> {:ok, true}
        {_, 32} -> {:error, "invalid mode #{mode}"}
        {_, n} -> {:error, "invalid size for compressed key #{n + 1}"}
      end

    with {:ok, odd?} <- test,
         x <- :binary.decode_unsigned(x_coord, :big),
         y_squared <- rem(IM.mod_pow(x, 3, p) + a * x + b, p),
         {:ok, y} <- IM.sqrt_mod(y_squared, p) do
      if odd? == Integer.is_odd(y) do
        {:ok, <<4::8>> <> to_hex_32(x) <> to_hex_32(y)}
      else
        {:ok, <<4::8>> <> to_hex_32(x) <> to_hex_32(p - y)}
      end
    end
  end

  def to_hex_32(i) do
    s = :binary.encode_unsigned(i)
    n_bytes = byte_size(s)

    if n_bytes < 32 do
      pad_size = (32 - n_bytes) * 8
      <<0::integer-size(pad_size)>> <> s
    else
      s
    end
  end
end
