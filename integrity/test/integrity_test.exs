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
        "cryptosuite" => "jcs-eddsa-2022",
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
        cryptosuite: "jcs-eddsa-2022"
      )

    assert transformed_document ==
             "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/data-integrity/v1\"],\"title\":\"new document\"}"

    proof_config =
      Integrity.proof_configuration!(@test_document,
        type: "DataIntegrityProof",
        cryptosuite: "jcs-eddsa-2022",
        created: @proof_config_created,
        verification_method: @verification_method_url,
        proof_purpose: "assertionMethod"
      )

    assert proof_config ==
             "{\"@context\":[\"https://www.w3.org/ns/did/v1\",\"https://w3id.org/security/data-integrity/v1\"],\"created\":\"2020-11-05T19:23:24Z\",\"cryptosuite\":\"jcs-eddsa-2022\",\"proofPurpose\":\"assertionMethod\",\"type\":\"DataIntegrityProof\",\"verificationMethod\":\"did:example:123456789abcdefghi#keys-1\"}"

    hash_data = Integrity.hash(proof_config, transformed_document)
    # assert CryptoUtils.display_byteshash_data) == ""

    assert hash_data ==
             <<238, 154, 157, 59, 112, 209, 224, 189, 75, 33, 108, 128, 166, 229, 99, 132, 111,
               99, 172, 217, 74, 32, 157, 154, 192, 176, 194, 50, 78, 123, 134, 104, 137, 202,
               252, 201, 116, 72, 95, 113, 101, 108, 231, 21, 70, 250, 142, 28, 30, 219, 184, 82,
               71, 117, 126, 33, 1, 187, 102, 74, 32, 31, 194, 227>>

    key_options = [
      public_key_bytes: @public_key_bytes,
      private_key_bytes: @private_key_bytes
    ]

    proof_bytes = Integrity.serialize_proof!(hash_data, key_options)
    # assert CryptoUtils.display_bytesproof_bytes) == ""

    assert proof_bytes ==
             <<236, 12, 31, 81, 196, 198, 187, 38, 102, 51, 173, 50, 216, 57, 22, 104, 218, 94, 6,
               9, 135, 139, 8, 193, 103, 117, 7, 109, 251, 20, 155, 179, 20, 60, 183, 7, 250, 216,
               121, 128, 127, 100, 17, 129, 161, 157, 127, 143, 79, 16, 132, 102, 20, 107, 245,
               183, 64, 223, 193, 194, 103, 1, 49, 0>>

    assert Integrity.verify_proof!(hash_data, proof_bytes, key_options)
  end

  test "creates an assertionMethod proof document" do
    proof_document =
      Integrity.build_assertion_proof!(@test_document,
        type: "DataIntegrityProof",
        cryptosuite: "jcs-eddsa-2022",
        created: @proof_config_created,
        verification_method: @verification_method_url,
        proof_purpose: "assertionMethod",
        public_key_bytes: @public_key_bytes,
        private_key_bytes: @private_key_bytes
      )

    assert %{"proof" => proof} = proof_document
    assert %{"proofValue" => proof_value} = proof
    # assert CryptoUtils.display_bytesproof_value) == ""
    assert proof_value ==
             "z5iisP3L5JS7gby3WCEMTg1ghf9x77iujzJv7fho1SJQg99sQR6eHGhSS22s2U9JenDhBfzSrJviFnuwjnau2eH3u"

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
        cryptosuite: "jcs-eddsa-2022",
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
