defmodule CryptoUtils.Did.Methods.DidKey do
  @moduledoc """
  Handler for the did:key method.
  """

  @behaviour CryptoUtils.Did.Method
  @behaviour CryptoUtils.Did.Resolver

  alias CryptoUtils.Did.{
    DocumentMetadata,
    ResolutionMetadata,
    EllipticCurveError,
    InvalidDidError
  }

  @ed25519_prefix <<0xED, 0x01>>
  @p256_prefix <<0x80, 0x24>>
  @secp256k1_prefix <<0xE7, 0x01>>

  # @bls12381_g2_prefix <<0xEB, 0x01>>
  # @p384_prefix <<0x81, 0x24>>
  # @rsa_prefix <<0x85, 0x24>>

  @impl CryptoUtils.Did.Method
  def name() do
    "key"
  end

  @impl CryptoUtils.Did.Method
  def to_resolver() do
    __MODULE__
  end

  @impl CryptoUtils.Did.Method
  def validate(%{did_string: identifier, method_specific_id: method_specific_id} = parsed, _) do
    {version, multibase_value} =
      case String.split(method_specific_id, ":") do
        [version, multibase_value] -> {version, multibase_value}
        [multibase_value] -> {"1", multibase_value}
        _ -> {nil, ""}
      end

    if String.starts_with?(multibase_value, "z") do
      {parsed, curve, pub} =
        case CryptoUtils.Keys.decode_multikey(multibase_value) do
          {:ok, {pub, curve}} ->
            {parsed, curve, pub}

          _ ->
            raise InvalidDidError, identifier
        end

      key_data = parse_key!(curve, pub)

      {:ok,
       parsed
       |> Map.merge(%{
         version: version,
         multibase_value: multibase_value
       })
       |> Map.merge(key_data)}
    else
      :error
    end
  end

  @impl CryptoUtils.Did.Resolver
  def resolve(
        %{
          did_string: identifier,
          method_specific_id: method_specific_id,
          vm_type: vm_type,
          vm_type_iri: vm_type_iri,
          jwk: jwk
        },
        _opts
      ) do
    context = [
      "https://www.w3.org/ns/did/v1",
      %{
        "publicKeyJwk" => %{
          "@id" => "https://w3id.org/security#publicKeyJwk",
          "@type" => "@json"
        }
      }
      |> Map.put(vm_type, vm_type_iri)
    ]

    vm_did_url = "#{identifier}##{method_specific_id}"

    doc = %{
      "@context" => context,
      "id" => identifier,
      "verificationMethod" => %{
        "id" => vm_did_url,
        "type" => vm_type,
        "controller" => identifier,
        "publicKeyJwk" => jwk
      },
      "authentication" => [vm_did_url],
      "assertionMethod" => [vm_did_url]
    }

    {:ok, {%ResolutionMetadata{}, doc, %DocumentMetadata{}}}
  end

  defp parse_key!(:ed25519 = curve, key_bytes) do
    %{
      curve: curve,
      key_bytes: key_bytes,
      jwk: CryptoUtils.Keys.make_public_key(key_bytes, curve, :jwk),
      jwt_alg: "ED25519",
      vm_type: "Ed25519VerificationKey2018",
      vm_type_iri: "https://w3id.org/security#Ed25519VerificationKey2018",
      algo_key: {:eddsa, [key_bytes, curve]}
    }
  end

  defp parse_key!(:p256 = curve, key_bytes) do
    case CryptoUtils.Curves.decompress_public_key_point(key_bytes, curve) do
      {:ok, uncompressed} ->
        %{
          curve: curve,
          key_bytes: key_bytes,
          jwk: CryptoUtils.Keys.make_public_key(uncompressed, curve, :jwk),
          jwt_alg: "ES256",
          vm_type: "EcdsaSecp256r1VerificationKey2019",
          vm_type_iri: "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019",
          algo_key: {:ecdsa, [uncompressed, :secp256r1]}
        }

      _ ->
        raise EllipticCurveError, "p256"
    end
  end

  defp parse_key!(:secp256k1 = curve, key_bytes) do
    case CryptoUtils.Curves.decompress_public_key_point(key_bytes, curve) do
      {:ok, uncompressed} ->
        %{
          curve: curve,
          key_bytes: key_bytes,
          jwk: CryptoUtils.Keys.make_public_key(uncompressed, curve, :jwk),
          jwt_alg: "ES256K",
          vm_type: "EcdsaSecp256k1VerificationKey2019",
          vm_type_iri: "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019",
          algo_key: {:ecdsa, [uncompressed, curve]}
        }

      _ ->
        raise EllipticCurveError, "secp256k1"
    end
  end
end
