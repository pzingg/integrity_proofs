defmodule DidServer.DidOrbClient do
  @moduledoc false

  @sha2_256_code 0x12
  @sha2_512_code 0x13

  alias CryptoUtils.Keys.Keypair

  @doc """
    * `sidetree_url` - endpoint
    * `doc` - a map or JSON DID document with `publicKeys`, `services` and `alsoKnownAs`
      components.
    * `update_keypair` and `recovery_keypair` - `:secp256k` keys in `:public_key` format.
    * `patches` - list of `add-public-keys`, etc. if `doc` is empty or nil

  Example of a doc:

  {
    "alsoKnownAs": ["https://myblog.example/"],
    "publicKey": [
      {
        "id": "createKey",
        "type": "JsonWebKey2020",
        "purposes": ["authentication"],
        "publicKeyJwk": {
          "kty": "EC",
          "crv": "P-256K",
          "x": "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0",
          "y": "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE"
        }
      },
      {
        "id": "auth",
        "type": "Ed25519VerificationKey2018",
        "purposes": ["assertionMethod"],
        "publicKeyJwk": {
          "kty": "OKP",
          "crv": "Ed25519",
          "alg": "EdDSA",
          "x": "TdGIibGMdQhIu7MGDXjYMTxrcPu8-SoE6D2sEiQI2os"
        }
      }
    ],
    "service": [
     {
       "id": "didcomm",
       "type": "did-communication",
       "recipientKeys": ["base58encoded_ed25519key_recipient_public_key_bytes"],
       "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/",
       "priority": 0
     }
    ]
  }
  """
  def build_create_request(
        doc,
        update_keypair,
        recovery_keypair,
        anchor_origin \\ nil,
        patches \\ [],
        algo \\ @sha2_256_code
      ) do
    doc =
      case doc do
        data when is_map(data) ->
          data

        s when is_binary(s) ->
          case Jason.decode(doc) do
            {:ok, data} when is_map(data) -> data
            _ -> nil
          end

        _ ->
          nil
      end

    patches =
      if is_nil(doc) do
        patches
      else
        patches_from_document(doc)
      end

    update_commitment = get_commitment(update_keypair)
    recovery_commitment = get_commitment(recovery_keypair)

    delta = %{
      "updateCommitment" => update_commitment,
      "patches" => patches
    }

    delta_hash = encode_multihash(delta, algo)

    suffix_data = %{
      "deltaHash" => delta_hash,
      "recoveryCommitment" => recovery_commitment
    }

    suffix_data =
      if is_nil(anchor_origin) do
        suffix_data
      else
        Map.put(suffix_data, "anchorOrigin", anchor_origin)
      end

    %{"type" => "create", "delta" => delta, "suffixData" => suffix_data}
  end

  defp get_commitment(%Keypair{public_key: public_key}) do
    {_, jwk} = public_key |> JOSE.JWK.from_key() |> JOSE.JWK.to_map()
    encode_multihash(jwk)
  end

  defp patches_from_document(doc) when is_binary(doc) do
    Jason.decode!(doc) |> patches_from_document()
  end

  defp patches_from_document(json_data) when is_map(json_data) do
    {keys, services, akas, patches} =
      Enum.reduce(json_data, {[], [], [], []}, fn
        {"publicKey", value}, {_keys, services, akas, adds} ->
          {List.wrap(value), services, akas, adds}

        {"service", value}, {keys, _services, akas, adds} ->
          {keys, List.wrap(value), akas, adds}

        {"alsoKnownAs", value}, {keys, services, _akas, adds} ->
          {keys, services, List.wrap(value), adds}

        {key, value}, {keys, services, akas, adds} ->
          {keys, services, akas, [%{"op" => "add", "path" => "/#{key}", "value" => value} | adds]}
      end)

    patches =
      if Enum.empty?(keys) do
        patches
      else
        [%{"action" => "add-public-keys", "publicKeys" => keys} | patches]
      end

    patches =
      if Enum.empty?(services) do
        patches
      else
        [%{"action" => "add-services", "services" => services} | patches]
      end

    if Enum.empty?(akas) do
      patches
    else
      [%{"action" => "add-also-known-as", "uris" => akas} | patches]
    end
  end

  defp encode_multihash(json_data, algo \\ @sha2_256_code) do
    calculate_multihash(json_data, algo)
    |> Base.url_encode64(padding: false)
  end

  defp calculate_multihash(json_data, @sha2_256_code) do
    encoded = Jcs.encode(json_data)
    digest = :crypto.hash(:sha256, encoded)

    <<@sha2_256_code, byte_size(digest), digest::binary>>
  end

  defp calculate_multihash(json_data, @sha2_512_code) do
    encoded = Jcs.encode(json_data)
    digest = :crypto.hash(:sha512, encoded)

    <<@sha2_512_code, byte_size(digest), digest::binary>>
  end

  defp calculate_multihash(_json_data, algo) do
    raise ArgumentError, message: "algorithm #{algo} not supported, unable to compute hash"
  end
end
