defmodule DidServer.DidOrbClientTest do
  use DidServer.DataCase

  alias DidServer.DidOrbClient

  @anchor_origin "http://orb.example.com:7890"

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
        recovery_keypair,
        @anchor_origin
      )

    delta_hash = get_in(request, ["suffixData", "deltaHash"])
    assert String.starts_with?(delta_hash, "Ei")
  end

  # Start orb server with
  # ./.build/bin/orb start --host-url="0.0.0.0:7890" --kms-type=local --cas-type=local --external-endpoint=http://localhost:7890 --did-namespace=test --database-type=mem --kms-secrets-database-type=mem --anchor-credential-domain=http://localhost:7890

  test "creates a new did:orb" do
    assert {:ok, orb_pid} =
             DidServer.DidOrbServer.start_link([listen_port: 7890, did_namespace: "did:test"], [])

    :timer.sleep(5000)

    assert {:ok, body} = CryptoUtils.Resolver.fetch("http://localhost:7890/healthcheck", [])
    assert {:ok, check} = Jason.decode(body)
    assert Map.get(check, "status") == "OK"

    update_keypair = CryptoUtils.Keys.Keypair.generate(:p256, :public_key)
    recovery_keypair = CryptoUtils.Keys.Keypair.generate(:p256, :public_key)

    doc = build_did_doc("https://myblog.example/", "key-1", "auth")

    request =
      DidOrbClient.build_create_request(
        doc,
        update_keypair,
        recovery_keypair,
        @anchor_origin
      )
      |> Jason.encode!()

    assert {:ok, body} =
             CryptoUtils.Resolver.fetch("http://localhost:7890/sidetree/v1/operations",
               method: :post,
               content_type: "application/json",
               body: request
             )

    result = Jason.decode!(body)
    document = Map.fetch!(result, "didDocument")
    document_metadata = Map.get(result, "didDocumentMetadata", %{})

    interim_did = Map.get(document, "id")
    equivalent_did = Map.get(document_metadata, "equivalentId", []) |> List.wrap() |> hd()

    assert String.starts_with?(interim_did, "did:test:uAAA:")
    assert String.starts_with?(equivalent_did, "did:test:https:localhost:7890:uAAA:")

    if false do
      :timer.sleep(5000)

      # {"level":"info","ts":"2023-08-18T21:12:37.078-0700","logger":"sidetree-core-writer","caller":"batch/writer.go:272",
      #   "msg":"Writing anchor string","namespace":"test","anchorString":"1.hl:uEiB6aWkawIYK0ieJgKW2sgLCeO7iXbyhJscSTOOZm2jHfA:uoQ-BeElodHRwOi8vbG9jYWxob3N0Ojc4OTAvY2FzL3VFaUI2YVdrYXdJWUswaWVKZ0tXMnNnTENlTzdpWGJ5aEpzY1NUT09abTJqSGZB"}

      # With anchor https://orb.example.com
      # {"level":"error","ts":"2023-08-18T21:12:37.256-0700","logger":"sidetree-core-writer","caller":"batch/writer.go:240",
      #   "msg":"Error processing batch operations","namespace":"test","total":1,
      #   "error":"write anchor [1.hl:uEiB6aWkawIYK0ieJgKW2sgLCeO7iXbyhJscSTOOZm2jHfA:uoQ-BeElodHRwOi8vbG9jYWxob3N0Ojc4OTAvY2FzL3VFaUI2YVdrYXdJWUswaWVKZ0tXMnNnTENlTzdpWGJ5aEpzY1NUT09abTJqSGZB]: failed to create witness list:
      #      resolve witness: failed to resolve witness:
      #      failed to get key[https://orb.example.com] from host metadata cache:
      #      failed to get a response from the host-meta endpoint: Get \"https://orb.example.com/.well-known/host-meta.json\":
      #      dial tcp: lookup orb.example.com on 127.0.0.53:53: no such host"}
      # {"level":"error","ts":"2023-08-18T21:18:19.982-0700","logger":"sidetree-core-writer","caller":"batch/writer.go:240",
      #   "msg":"Error processing batch operations","namespace":"test","total":1,
      #   "error":"write anchor [1.hl:uEiBUv8eEayWkwYmZ3dd58khV1ryPmIyvsoj5_1W0XuTBcw:uoQ-BeElodHRwOi8vbG9jYWxob3N0Ojc4OTAvY2FzL3VFaUJVdjhlRWF5V2t3WW1aM2RkNThraFYxcnlQbUl5dnNvajVfMVcwWHVUQmN3]: failed to create witness list:
      #      resolve witness: failed to resolve witness:
      #      failed to get key[https://orb.example.com] from host metadata cache:
      #      failed to get a response from the host-meta endpoint: Get \"https://orb.example.com/.well-known/host-meta.json\":
      #      tls: failed to verify certificate:
      #      x509: certificate has expired or is not yet valid:
      #      current time 2023-08-18T21:18:19-07:00 is after 2019-10-03T17:25:24Z"}

      # With anchor http://orb.example.com:7890. protocolVersion is 0, should be 1?
      # {"level":"error","ts":"2023-08-18T21:26:02.389-0700","logger":"sidetree-core-writer","caller":"batch/writer.go:240",
      #    "msg":"Error processing batch operations","namespace":"test","total":1,
      #    "error":"write anchor [1.hl:uEiDqSwbSyRz5LE3m4vPimGJBiK8wnlK6j8FoGe6eIccZkg:uoQ-BeElodHRwOi8vbG9jYWxob3N0Ojc4OTAvY2FzL3VFaURxU3diU3lSejVMRTNtNHZQaW1HSkJpSzh3bmxLNmo4Rm9HZTZlSWNjWmtn]:
      #       build anchor linkset for core index [hl:uEiDqSwbSyRz5LE3m4vPimGJBiK8wnlK6j8FoGe6eIccZkg:uoQ-BeElodHRwOi8vbG9jYWxob3N0Ojc4OTAvY2FzL3VFaURxU3diU3lSejVMRTNtNHZQaW1HSkJpSzh3bmxLNmo4Rm9HZTZlSWNjWmtn]:
      #       build content object: generator not found for namespace [test] and version [0]:
      #       content not found"}

      aliased_did = String.replace_leading(interim_did, "test:", "did:orb:")
      assert {:ok, body} =
              CryptoUtils.Resolver.fetch(
                "http://localhost:7890/sidetree/v1/identifiers/#{interim_did}",
                []
              )
    end
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
