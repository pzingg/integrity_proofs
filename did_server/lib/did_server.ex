defmodule DidServer do
  @moduledoc """
  Elixir implementation of Bluesky's did:plc method.

  See https://github.com/bluesky-social/did-method-plc
  """

  require Integer

  alias CryptoUtils.CID

  defmodule CreateOpV1 do
    defstruct [
      :signing_key,
      :recovery_key,
      :signer,
      :handle,
      :service,
      :prev,
      :sig,
      type: "create"
    ]
  end

  defmodule EllipticCurveError do
    defexception [:message]

    @impl true
    def exception(curve) do
      %__MODULE__{message: "Point not on elliptic curve #{curve}"}
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

  defmodule InvalidSignatureError do
    defexception [:message]

    @impl true
    def exception(_op) do
      %__MODULE__{message: "invalid signature"}
    end
  end

  defmodule LateRecoveryError do
    defexception [:message]

    @impl true
    def exception(lapsed) do
      %__MODULE__{message: "72 hour recovery period exceeded: #{lapsed} seconds"}
    end
  end

  defmodule MisorderedOperationError do
    defexception []

    @impl true
    def message(_) do
      "misordered plc operation"
    end
  end

  defmodule MissingSignatureError do
    defexception [:message]

    @impl true
    def exception(_op) do
      %__MODULE__{message: "operation is missing signature"}
    end
  end

  defmodule PrevMismatchError do
    defexception [:message]
  end

  defmodule UnsupportedKeyError do
    defexception [:message]

    @impl true
    def exception(key) do
      %__MODULE__{message: "Unsupported key #{key}"}
    end
  end

  defmodule UnsupportedPublicKeyCodecError do
    defexception [:message]

    @impl true
    def exception(prefix) do
      %__MODULE__{message: "Unsupported public key codec #{prefix}"}
    end
  end

  # @p256_code 0x1200
  @p256_prefix <<0x80, 0x24>>
  @p256_jwt_alg "ES256"

  # @secp256k1_code 0xE7
  @secp256k1_prefix <<0xE7, 0x01>>
  @secp256k1_jwt_alg "ES256K"

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
      CryptoUtils.Did.parse_did!(did, expected_did_method: "key")

    prefixed_bytes = Multibase.decode!(multibase_value)
    <<b0::size(8), b1::size(8)>> <> key_bytes = prefixed_bytes
    prefix = <<b0::size(8), b1::size(8)>>

    case prefix do
      @p256_prefix ->
        case CryptoUtils.Curves.decompress_public_key_point(key_bytes, :p256) do
          {:ok, uncompressed} ->
            %{
              jwt_alg: @p256_jwt_alg,
              key_bytes: prefixed_bytes,
              algo_key: {:ecdsa, [uncompressed, :p256]}
            }

          _ ->
            raise EllipticCurveError, "p256"
        end

      @secp256k1_prefix ->
        case CryptoUtils.Curves.decompress_public_key_point(key_bytes, :secp256k1) do
          {:ok, uncompressed} ->
            %{
              jwt_alg: @secp256k1_jwt_alg,
              key_bytes: prefixed_bytes,
              algo_key: {:ecdsa, [uncompressed, :secp256k1]}
            }

          _ ->
            raise EllipticCurveError, "secp256k1"
        end

      _ ->
        raise UnsupportedPublicKeyCodecError, prefix
    end
  end

  # Operations

  def create_op(params) do
    %CreateOpV1{signer: signer} = op = struct(CreateOpV1, params)

    op = op |> normalize_op() |> add_signature(signer)
    did = did_for_create_op(op)
    {op, did}
  end

  def did_for_create_op(%{"prev" => nil} = op) do
    cbor = CBOR.encode(op)
    hash_of_genesis = :crypto.hash(:sha256, cbor)

    truncated_id =
      hash_of_genesis |> Base.encode32(case: :lower, padding: false) |> String.slice(0, 24)

    "did:plc:#{truncated_id}"
  end

  def cid_for_op(op) do
    op
    |> CID.from_data()
    |> CID.encode!(truncate: 24)
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

  # Signatures

  def add_signature(op, {_, signing_key}) do
    # {:ecdsa, [<<binary-size::32>>, :secp256k1]}
    {algorithm, [priv, curve]} = signing_key

    cbor = CBOR.encode(op)
    signature = :crypto.sign(algorithm, :sha256, cbor, [priv, curve], [])
    Map.put(op, "sig", Base.encode64(signature))
  end

  def verify_signature(did_key, cbor, sig_bytes) do
    %{algo_key: algo_key} = parse_did_key!(did_key)
    # {:ecdsa, [<<binary-size::65>>, :secp256k1]}
    {algorithm, [pub, curve]} = algo_key

    :crypto.verify(algorithm, :sha256, cbor, sig_bytes, [pub, curve], [])
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

  def assure_valid_creation_op(_did, %{"type" => "plc_tombstone"}) do
    raise MisorderedOperationError
  end

  def assure_valid_creation_op(did, %{"rotationKeys" => rotation_keys, "prev" => prev} = op) do
    if !is_nil(prev) do
      raise ImproperOperationError, op: op, message: "expected null prev on create"
    end

    assure_valid_op(op)
    assure_valid_sig(rotation_keys, op)
    expected_did = did_for_create_op(op)

    if did != expected_did do
      raise GenesisHashError, expected_did
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
        _e ->
          raise UnsupportedKeyError, key
      end
    end)

    if Enum.count(rotation_keys) > 5 do
      raise ImproperOperationError, op: op, message: "too many rotation keys"
    end

    assure_rotation_keys(op, rotation_keys)
  end

  def assure_rotation_keys(op, rotation_keys) do
    if Enum.empty?(rotation_keys) do
      raise ImproperOperationError, op: op, message: "need at least one rotation key"
    end

    op
  end

  def assure_valid_sig(allowed_did_keys, %{"sig" => sig} = op) when is_binary(sig) do
    _ = assure_rotation_keys(op, allowed_did_keys)

    with {:ok, sig_bytes} <- Base.decode64(sig),
         cbor <- Map.delete(op, "sig") |> normalize_op() |> CBOR.encode() do
      valid =
        Enum.find(allowed_did_keys, fn did_key ->
          verify_signature(did_key, cbor, sig_bytes)
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

  def assure_valid_sig(_allowed_did_keys, op) do
    raise MissingSignatureError, op
  end

  def format_service({service_id, %{type: type, endpoint: endpoint}}) do
    {service_id, %{"type" => type, "endpoint" => endpoint}}
  end
end
