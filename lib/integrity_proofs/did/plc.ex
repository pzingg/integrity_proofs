defmodule IntegrityProofs.Did.Plc do
  @moduledoc """
  Elixir implementation of Bluesky's did:plc method.

  See https://github.com/bluesky-social/did-method-plc
  """

  require Integer

  alias IntegrityProofs.Math, as: IM

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
