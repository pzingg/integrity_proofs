defmodule DidServer.DidOrbClientTest do
  use DidServer.DataCase

  alias DidServer.DidOrbClient

  @example_doc """
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

  test "builds a sidetree create did document" do
    update_keypair = CryptoUtils.Keys.Keypair.generate(:p256, :public_key)
    recovery_keypair = CryptoUtils.Keys.Keypair.generate(:p256, :public_key)

    doc = build_did_doc("https://myblog.example/", "key-1", "auth")

    request =
      DidOrbClient.build_create_request(
        doc,
        update_keypair,
        recovery_keypair
      )

    delta_hash = get_in(request, ["suffixData", "deltaHash"])
    assert String.starts_with?(delta_hash, "Ei")
  end

  defp build_did_doc(aka, assertion_key, auth_key) do
    %{public_key: {{:ECPoint, assertion_public_bytes}, _}} =
      CryptoUtils.Keys.Keypair.generate(:ed25519, :public_key)

    {_, assertion_jwk} =
      {:Ed25519, assertion_public_bytes} |> JOSE.JWK.from_okp() |> JOSE.JWK.to_map()

    %{public_key: auth_public_key} = CryptoUtils.Keys.Keypair.generate(:secp256k1, :public_key)
    {_, auth_jwk} = auth_public_key |> JOSE.JWK.from_key() |> JOSE.JWK.to_map()

    %{public_key: recipient_multikey} = CryptoUtils.Keys.Keypair.generate(:ed25519, :multikey)

    %{
      "alsoKnownAs" => List.wrap(aka),
      "publicKey" => [
        %{
          "id" => assertion_key,
          "type" => "Ed25519VerificationKey2018",
          "purposes" => ["assertionMethod"],
          "publicKeyJwk" => assertion_jwk
        },
        %{
          "id" => auth_key,
          "type" => "JsonWebKey2020",
          "purposes" => ["authentication"],
          "publicKeyJwk" => auth_jwk
        }
      ],
      "service" => [
        %{
          "id" => "didcomm",
          "type" => "did-communication",
          "recipientKeys" => [recipient_multikey],
          "serviceEndpoint" => "https://hub.example.com/.identity/did:example:0123456789abcdef/",
          "priority" => 0
        }
      ]
    }
  end
end
