defmodule CryptoUtils.Did.Methods.DidKey do
  @moduledoc """
  Handler for the did:key method.
  """

  @behaviour CryptoUtils.Did.Method
  @behaviour CryptoUtils.Did.Resolver

  alias CryptoUtils.Did.{
    DocumentMetadata,
    ResolutionInputMetadata,
    ResolutionMetadata,
    EllipticCurveError,
    InvalidDidError,
    UnsupportedPublicKeyCodecError
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

  @impl CryptoUtils.Did.Resolver
  def resolve(_module, did, _input_metadata) do
    if !String.starts_with?(did, "did:key:") do
      error_result("invalid Did")
    else
      try do
        %{
          vm_type: vm_type,
          vm_type_iri: vm_type_iri,
          jwk: jwk,
          method_specific_id: method_specific_id
        } = parse!(did)

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

        vm_did_url = "#{did}##{method_specific_id}"

        doc = %{
          "@context" => context,
          "id" => did,
          "verificationMethod" => %{
            "id" => vm_did_url,
            "type" => vm_type,
            "controller" => did,
            "publicKeyJwk" => jwk
          },
          "authentication" => [vm_did_url],
          "assertionMethod" => [vm_did_url]
        }

        {:ok, {%ResolutionMetadata{}, doc, %DocumentMetadata{}}}
      rescue
        e ->
          error_result(Exception.message(e))
      end
    end
  end

  @impl CryptoUtils.Did.Resolver
  def resolve_representation(_module, _did, _input_metadata) do
    error_result("TODO")
  end

  def parse!(did) do
    {parsed, curve, pub} =
      try do
        %{multibase_value: multibase_value} =
          parsed = CryptoUtils.Did.parse_did!(did, expected_did_methods: :key)

        case CryptoUtils.Keys.decode_multikey(multibase_value) do
          {:ok, {pub, curve}} ->
            {parsed, curve, pub}

          _ ->
            raise InvalidDidError, did
        end
      rescue
        _ ->
          raise InvalidDidError, did
      end

    key_data = parse_key!(curve, pub)
    Map.merge(key_data, parsed)
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

  defp error_result(error) do
    {:error, {%ResolutionMetadata{error: error}, nil, nil}}
  end
end
