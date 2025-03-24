defmodule CryptoUtils.Did.Methods.DidKey do
  @moduledoc """
  Handler for the did:key method.
  """

  @behaviour CryptoUtils.Did.Method
  @behaviour CryptoUtils.Did.Resolver

  alias CryptoUtils.Did.{
    DocumentMetadata,
    ResolutionMetadata,
    InvalidDidError
  }

  alias CryptoUtils.Keys.KeyFormat

  # @ed25519_prefix <<0xED, 0x01>>
  # @p256_prefix <<0x80, 0x24>>
  # @secp256k1_prefix <<0xE7, 0x01>>

  # @bls12381_g2_prefix <<0xEB, 0x01>>
  # @p384_prefix <<0x81, 0x24>>
  # @rsa_prefix <<0x85, 0x24>>

  @impl CryptoUtils.Did.Method
  def name() do
    "key"
  end

  @impl CryptoUtils.Did.Method
  def generate(public_key) when is_binary(public_key) do
    cond do
      String.starts_with?(public_key, "did:key:") ->
        public_key

      String.starts_with?(public_key, "z") ->
        case CryptoUtils.Keys.decode_multikey(public_key) do
          {:ok, {pub, curve}} ->
            CryptoUtils.Keys.make_public_key(pub, curve, :did_key)

          _ ->
            nil
        end

      true ->
        nil
    end
  end

  def generate({:ecdsa, [pub, curve]}) do
    CryptoUtils.Keys.make_public_key(pub, curve, :did_key)
  end

  def generate({:eddsa, [pub, curve]}) do
    CryptoUtils.Keys.make_public_key(pub, curve, :did_key)
  end

  def generate(%{"kty" => _}) do
    # TODO get pub bytes via jose_jwk
    nil
  end

  def generate(_) do
    nil
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

      key_data = KeyFormat.parse_public_key(curve, pub)

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
          method: :key,
          method_specific_id: method_specific_id,
          jwk: jwk,
          multibase_value: multibase_value
        },
        _opts
      ) do
    context = [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/jwk/v1",
      "https://w3id.org/security/multikey/v1"
    ]

    jwk_vm_did_url = identifier <> "#" <> method_specific_id
    mk_vm_did_url = identifier <> "#keys-1"

    doc = %{
      "@context" => context,
      "id" => identifier,
      "verificationMethod" => [
        %{
          "id" => jwk_vm_did_url,
          "type" => "JasonWebKey2020",
          "controller" => identifier,
          "publicKeyJwk" => jwk
        },
        %{
          "id" => mk_vm_did_url,
          "type" => "Multikey",
          "controller" => identifier,
          "publicKeyMultibase" => multibase_value
        }
      ],
      "authentication" => [jwk_vm_did_url, mk_vm_did_url],
      "assertionMethod" => [jwk_vm_did_url, mk_vm_did_url]
    }

    {:ok, {%ResolutionMetadata{}, doc, %DocumentMetadata{}}}
  end
end
