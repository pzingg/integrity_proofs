defmodule IntegrityTest do
  use ExUnit.Case
  doctest Integrity

  require Multibase

  @public_key_bytes <<243, 105, 212, 154, 54, 128, 250, 99, 47, 184, 242, 248, 144, 45, 17, 70,
                      176, 243, 220, 174, 103, 200, 4, 192, 33, 143, 102, 29, 234, 149, 1, 188>>

  @public_key_multibase CryptoUtils.Keys.make_public_key(@public_key_bytes, :ed25519, :multikey)

  @private_key_bytes <<112, 38, 151, 226, 182, 82, 47, 205, 7, 158, 217, 27, 159, 218, 142, 29,
                       117, 44, 83, 74, 35, 121, 140, 91, 190, 215, 239, 144, 58, 42, 1, 200>>

  @test_document %{
    "@context" => [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/data-integrity/v1"
    ],
    "title" => "new document"
  }

  @proof_config_created "2020-11-05T19:23:24Z"

  @controller_url "did:example:123"
  @controller_document_url "did:example:123456789abcdefghi"
  @verification_method_url "did:example:123456789abcdefghi#keys-1"

  @controller_document %{
    "@context" => [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/multikey/v1"
    ],
    "id" => @controller_document_url,
    "verificationMethod" => [
      %{
        "id" => @verification_method_url,
        "type" => "Multikey",
        "cryptosuite" => "eddsa-jcs-2022",
        "controller" => @controller_url,
        "publicKeyMultibase" => @public_key_multibase
      }
    ]
  }

  test "retrieves a private key" do
    key_options = [
      public_key_bytes: @public_key_bytes,
      private_key_bytes: @private_key_bytes
    ]

    private_key = Integrity.retrieve_private_key!(key_options, :public_key)

    assert {:ECPrivateKey, 1, @private_key_bytes, {:namedCurve, {1, 3, 101, 112}},
            @public_key_bytes} = private_key

    assert {:eddsa, [@private_key_bytes, :ed25519]} = :dbg_public_key.format_sign_key(private_key)
  end

  test "signs a document" do
    transformed_document =
      Integrity.transform_jcs_eddsa_2022!(@test_document,
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022"
      )

    assert transformed_document ==
             "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/data-integrity/v1\"],\"title\":\"new document\"}"

    proof_config =
      Integrity.proof_configuration!(@test_document,
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        created: @proof_config_created,
        verification_method: @verification_method_url,
        proof_purpose: "assertionMethod"
      )

    assert proof_config ==
             "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/data-integrity/v1\"],\"created\":\"2020-11-05T19:23:24Z\",\"cryptosuite\":\"eddsa-jcs-2022\",\"proofPurpose\":\"assertionMethod\",\"type\":\"DataIntegrityProof\",\"verificationMethod\":\"did:example:123456789abcdefghi#keys-1\"}"

    hash_data = Integrity.hash(proof_config, transformed_document)
    # assert CryptoUtils.display_bytes(hash_data) == ""

    assert hash_data ==
             <<238, 21, 238, 66, 93, 235, 156, 213, 203, 246, 23, 225, 219, 193, 128, 128, 32,
               173, 71, 76, 30, 8, 173, 167, 206, 83, 54, 247, 147, 55, 167, 18, 137, 202, 252,
               201, 116, 72, 95, 113, 101, 108, 231, 21, 70, 250, 142, 28, 30, 219, 184, 82, 71,
               117, 126, 33, 1, 187, 102, 74, 32, 31, 194, 227>>

    key_options = [
      public_key_bytes: @public_key_bytes,
      private_key_bytes: @private_key_bytes
    ]

    proof_bytes = Integrity.serialize_proof!(hash_data, key_options)
    # assert CryptoUtils.display_bytes(proof_bytes) == ""

    assert proof_bytes ==
             <<11, 207, 227, 35, 205, 61, 191, 58, 123, 123, 92, 178, 20, 18, 42, 8, 93, 126, 99,
               72, 254, 9, 35, 237, 196, 216, 183, 100, 125, 37, 142, 75, 170, 85, 204, 157, 88,
               164, 111, 216, 210, 120, 105, 237, 241, 225, 94, 8, 199, 154, 105, 112, 53, 231,
               190, 143, 25, 145, 191, 153, 119, 248, 147, 4>>

    assert Integrity.verify_proof!(hash_data, proof_bytes, key_options)
  end

  test "creates an assertionMethod proof document" do
    proof_document =
      Integrity.build_assertion_proof!(@test_document,
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        created: @proof_config_created,
        verification_method: @verification_method_url,
        proof_purpose: "assertionMethod",
        public_key_bytes: @public_key_bytes,
        private_key_bytes: @private_key_bytes
      )

    assert %{"proof" => proof} = proof_document
    assert %{"proofValue" => proof_value} = proof

    assert proof_value ==
             "zEhSpwfgbZuAYYbpqKC1z4qAkvQtJ36CLvYiaLaYA1DiMQomtUsmgP5iwAjd5e4sXcMQEijWLFhTdAKPUYURuHJj"

    assert String.starts_with?(@public_key_multibase, "z6")

    verification_method =
      Integrity.verification_method!(proof, cached_controller_document: @controller_document)

    assert verification_method

    assert {:ok, public_key} =
             CryptoUtils.Keys.extract_multikey(verification_method, :crypto_algo_key)

    assert {:eddsa, [@public_key_bytes, :ed25519]} = public_key
  end

  test "verifies a proof document" do
    proof_document =
      Integrity.build_assertion_proof!(@test_document,
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        created: @proof_config_created,
        verification_method: @verification_method_url,
        proof_purpose: "assertionMethod",
        public_key_bytes: @public_key_bytes,
        private_key_bytes: @private_key_bytes
      )

    assert Integrity.verify_proof_document!(proof_document,
             expected_proof_purpose: "assertionMethod",
             cached_controller_document: @controller_document
           )
  end
end
