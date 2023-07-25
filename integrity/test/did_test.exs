defmodule Integrity.DidTest do
  use ExUnit.Case

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @identifier CryptoUtils.Keys.make_public_key(@public_key_bytes, :ed25519, :did_key)

  # A did document with both AT Protocol and ActivityPub data
  @did_document %{
    "@context" => [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/data-integrity/v1",
      "https://w3id.org/security/suites/ed25519-2020/v1",
      "https://w3id.org/security/suites/secp256k1-2019/v1",
      "https://w3id.org/security/suites/ecdsa-2019/v1"
    ],
    "id" => @identifier,
    "alsoKnownAs" => [
      "at://alice.bsky.social",
      "https://example.com/users/alice"
    ],
    "verificationMethod" => [
      %{
        "id" => "#{@identifier}#keys-1",
        "type" => "Multikey",
        "controller" => @identifier,
        "publicKeyMultibase" => "z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV"
      },
      %{
        "id" => "#atproto",
        "type" => "EcdsaSecp256k1VerificationKey2019",
        "controller" => @identifier,
        "publicKeyMultibase" => "z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV"
      }
    ],
    "assertionMethod" => [
      "#{@identifier}#keys-1"
    ],
    "authentication" => [
      "#{@identifier}#keys-1"
    ],
    "capabilityDelegation" => [
      "#{@identifier}#keys-1"
    ],
    "capabilityInvocation" => [
      "#{@identifier}#keys-1"
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

  test "builds a DID document" do
    document =
      CryptoUtils.Did.format_did_document!(@identifier,
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
end
