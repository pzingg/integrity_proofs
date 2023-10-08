defmodule CryptoUtils.DidTest do
  use ExUnit.Case

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @did_key_identifier CryptoUtils.Keys.make_public_key(@public_key_bytes, :ed25519, :did_key)

  @multibase_value CryptoUtils.Keys.make_public_key(@public_key_bytes, :ed25519, :multikey)

  @did_web_identifier "did:web:server.example:users:alice"

  # A did document with both AT Protocol and ActivityPub data
  @did_document %{
    "@context" => [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/data-integrity/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
      "https://w3id.org/security/suites/secp256k1-2019/v1",
      "https://w3id.org/security/suites/ecdsa-2019/v1"
    ],
    "id" => @did_key_identifier,
    "alsoKnownAs" => [
      "at://alice.bsky.social",
      "https://example.com/users/alice"
    ],
    "verificationMethod" => [
      %{
        "id" => "#{@did_key_identifier}#keys-1",
        "type" => "Multikey",
        "controller" => @did_key_identifier,
        "publicKeyMultibase" => "z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV"
      },
      %{
        "id" => "#atproto",
        "type" => "EcdsaSecp256k1VerificationKey2019",
        "controller" => @did_key_identifier,
        "publicKeyMultibase" => "z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV"
      }
    ],
    "assertionMethod" => [
      "#{@did_key_identifier}#keys-1"
    ],
    "authentication" => [
      "#{@did_key_identifier}#keys-1"
    ],
    "capabilityDelegation" => [
      "#{@did_key_identifier}#keys-1"
    ],
    "capabilityInvocation" => [
      "#{@did_key_identifier}#keys-1"
    ],
    "service" => [
      %{
        "id" => "#activitypub",
        "type" => "ActivityPubServer",
        "serviceEndpoint" => "https://example.com"
      },
      %{
        "id" => "#atproto_pds",
        "type" => "AtprotoPersonalDataServer",
        "serviceEndpoint" => "https://pds.example.com"
      }
    ]
  }

  def setup_test_server() do
    TestServer.start()

    TestServer.add("/users/alice/did.json",
      to: fn conn ->
        body =
          CryptoUtils.Did.format_did_document!(@did_web_identifier,
            multibase_value: @multibase_value,
            signature_method_fragment: "keys-1"
          )
          |> Jason.encode!()

        conn
        |> Plug.Conn.put_resp_header("content-type", "application/json")
        |> Plug.Conn.send_resp(200, body)
      end
    )
  end

  def fetch(url, opts) do
    %URI{path: path} = URI.parse(url)

    url =
      TestServer.url(path)
      |> String.to_charlist()

    CryptoUtils.HttpClient.fetch(url, opts)
  end

  test "builds a DID document" do
    document =
      CryptoUtils.Did.format_did_document!(@did_key_identifier,
        multibase_value: @multibase_value,
        also_known_as: [
          "at://alice.bsky.social",
          "https://example.com/users/alice"
        ],
        services: %{
          "atproto_pds" => %{
            type: "AtprotoPersonalDataServer",
            endpoint: "https://pds.example.com"
          },
          "activitypub" => %{
            type: "ActivityPubServer",
            endpoint: "https://example.com"
          }
        },
        additional_vms: %{
          "atproto" => %{
            context: [
              "https://w3id.org/security/suites/secp256k1-2019/v1",
              "https://w3id.org/security/suites/ecdsa-2019/v1"
            ],
            type: "EcdsaSecp256k1VerificationKey2019",
            value_type: "publicKeyMultibase",
            value: "z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV"
          }
        },
        signature_method_fragment: "keys-1",
        encryption_method_fragment: "keys-2",
        enable_encryption_key_derivation: false
      )

    assert @did_document = document
  end

  test "decodes and uncompresses a p256 did:key" do
    assert %{jwt_alg: _jwt_alg, algo_key: algo_key} =
             CryptoUtils.Did.parse_did!(
               "did:key:zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt"
             )

    assert {:ecdsa, [key_bytes, :secp256r1]} = algo_key
    assert byte_size(key_bytes) == 65
  end

  test "resolves a p256 did:key identifier" do
    assert {:ok, {_res_meta, doc, _doc_meta}} =
             CryptoUtils.Did.resolve_did!(
               "did:key:zDnaedvvAsDE6H3BDdBejpx9ve2Tz95cymyCAKF66JbyMh1Lt",
               []
             )

    assert doc["verificationMethod"]["publicKeyJwk"]["kty"] == "EC"
    assert doc["verificationMethod"]["publicKeyJwk"]["crv"] == "P-256"
  end

  describe "did:web test server" do
    test "resolves manually" do
      setup_test_server()

      {:ok, uri} = CryptoUtils.Did.Methods.DidWeb.did_web_uri(@did_web_identifier)
      url = URI.to_string(uri)
      assert url == "https://server.example/users/alice/did.json"

      resp = fetch(url, method: :get, headers: [{"accept", "application/json"}])
      assert {:ok, doc_data} = resp
      assert {:ok, doc} = Jason.decode(doc_data)
      assert doc["id"] == @did_web_identifier
    end

    test "resolves using method module" do
      setup_test_server()

      assert {:ok, {_, doc, _}} =
               CryptoUtils.Did.resolve_did!(@did_web_identifier, client: __MODULE__)

      assert doc["id"] == @did_web_identifier
    end
  end
end
