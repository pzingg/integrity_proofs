defmodule IntegrityProofs.DidTest do
  use ExUnit.Case

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @identifier IntegrityProofs.make_public_key(@public_key_bytes, :ed25519, :did_key)

  @did_document %{
    "@context" => [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/data-integrity/v1"
    ],
    "id" => @identifier,
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
    "verificationMethod" => [
      %{
        "id" => "#{@identifier}#keys-1",
        "type" => "Multikey",
        "controller" => @identifier,
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
