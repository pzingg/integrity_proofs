defmodule IntegrityProofs.ActivityPubTest do
  use ExUnit.Case

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @private_key_bytes <<112, 38, 151, 226, 182, 82, 47, 205, 7, 158, 217, 27, 159, 218, 142, 29,
                       117, 44, 83, 74, 35, 121, 140, 91, 190, 215, 239, 144, 58, 42, 1, 200>>

  @proof_config_created "2020-11-05T19:23:24Z"
  @verification_method_url "did:example:123456789abcdefghi#keys-1"

  @test_person %{
    "type" => "Person",
    "id" => "https://server.example/users/alice",
    "inbox" => "https://server.example/users/alice/inbox",
    "outbox" => "https://server.example/users/alice/outbox"
  }

  test "builds an fep-c390 identity proof document" do
    person_with_identity_proof =
      IntegrityProofs.ActivityPub.build_identity_proof!(@test_person,
        type: "DataIntegrityProof",
        cryptosuite: "jcs-eddsa-2022",
        created: @proof_config_created,
        verification_method: @verification_method_url,
        proof_purpose: "assertionMethod",
        public_key_bytes: @public_key_bytes,
        private_key_bytes: @private_key_bytes
      )

    assert %{"id" => _actor_id} = person_with_identity_proof

    assert person_with_identity_proof["attachment"] == [
             %{
               "type" => "VerifiableIdentityStatement",
               "subject" => "did:example:123456789abcdefghi#keys-1",
               "alsoKnownAs" => "https://server.example/users/alice",
               "proof" => %{
                 "created" => "2020-11-05T19:23:24Z",
                 "cryptosuite" => "jcs-eddsa-2022",
                 "proofPurpose" => "assertionMethod",
                 "proofValue" =>
                   "z2uFJT9DG444yJi5jdT5mV4Mv8moGEsbt3WyscJvzxbVREvJjyrDFmtfoUFBX7pfHoq2n52dfa1xt2ETh8HASBcfy",
                 "type" => "DataIntegrityProof",
                 "verificationMethod" => "did:example:123456789abcdefghi#keys-1"
               }
             }
           ]
  end

  test "verifies an fep-c390 identity proof document" do
    person_with_identity_proof =
      IntegrityProofs.ActivityPub.build_identity_proof!(@test_person,
        type: "DataIntegrityProof",
        cryptosuite: "jcs-eddsa-2022",
        created: @proof_config_created,
        verification_method: @verification_method_url,
        proof_purpose: "assertionMethod",
        public_key_bytes: @public_key_bytes,
        private_key_bytes: @private_key_bytes
      )

    assert IntegrityProofs.ActivityPub.verify_identity_proof!(person_with_identity_proof,
             public_key_bytes: @public_key_bytes,
             private_key_bytes: @private_key_bytes
           )
  end
end