defmodule IntegrityProofs.DidTest do
  use ExUnit.Case

  require Multibase

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @identifier IntegrityProofs.make_ed25519_public_key(@public_key_bytes, :did_key)

  @did_document %{
    "@context" => [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/data-integrity/v1"
    ],
    "id" => "did:key:z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV",
    "assertionMethod" => [
      "did:key:z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV#keys-1"
    ],
    "authentication" => [
      "did:key:z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV#keys-1"
    ],
    "capabilityDelegation" => [
      "did:key:z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV#keys-1"
    ],
    "capabilityInvocation" => [
      "did:key:z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV#keys-1"
    ],
    "verificationMethod" => [
      %{
        "id" => "did:key:z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV#keys-1",
        "type" => "Multikey",
        "controller" => "did:key:z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV",
        "publicKeyMultibase" => "z6MkvqSiJweFXrZmmdQgRR1A6vANr1S4qoyKVrVwVXSnBFdV"
      }
    ]
  }

  test "builds a DID document" do
    document =
      IntegrityProofs.Did.build_did_document!(@identifier,
        signature_method_fragment: "keys-1",
        encryption_method_fragment: "keys-2",
        enable_encryption_key_derivation: false
      )

    assert @did_document = document
  end
end
