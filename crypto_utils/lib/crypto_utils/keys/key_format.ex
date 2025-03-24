defmodule CryptoUtils.Keys.KeyFormat do
  @moduledoc """
  https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#key-formats
  give examples of how to use standard documents about key formats for verification.

  Examples of these sorts of documents include the key types in these specifications:
    - [Multikey2021 JSON-LD Context](https://ns.did.ai/suites/multikey-2021/v1/)
    - [Linked Data Cryptographic Suite Registry 2020](https://w3c-ccg.github.io/ld-cryptosuite-registry/)
    - [Security Vocabulary 2022](https://w3c-ccg.github.io/security-vocab/)
    - [DID Specification Registries 2023](https://w3c.github.io/did-spec-registries/#verification-method-types) for Verification Method Types

  Ideally, the specification would define all possible multikeys listed in the
  [Multicodec Registry table](https://github.com/multiformats/multicodec/blob/master/table.csv)
  and define how to encode them as multibase values in fields such as
  `publicKeyMultibase` and `secretKeyMultibase`.
  """

  import Bitwise

  # EXAMPLE 8: Verification methods using publicKeyJwk and publicKeyMultibase
  @vc_example """
  {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/jwk/v1",
      "https://w3id.org/security/multikey/v1"
    ]
    "id": "did:example:123456789abcdefghi",
    "verificationMethod": [
      {
        "id": "did:example:123#_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A",
        "type": "JsonWebKey",
        "controller": "did:example:123",
        "publicKeyJwk": {
          "crv": "Ed25519",
          "x": "VCpo2LMLhn6iWku8MKvSLg2ZAoC-nlOyPVQaO3FxVeQ",
          "kty": "OKP",
          "kid": "_Qq0UL2Fq651Q0Fjd6TvnYE-faHiOpRlPVQcY_-tA4A"
        }
      },
      {
        "id": "did:example:123456789abcdefghi#keys-1",
        "type": "Multikey",
        "controller": "did:example:pqrstuvwxyz0987654321",
        "publicKeyMultibase": "z6MkmM42vxfqZQsv4ehtTjFFxQ4sQKS2w6WR7emozFAn5cxu"
      }
    ]
  }
  """

  @verification_key_formats [
    %{
      format: "EcdsaSecp256k1VerificationKey2019",
      curves: [:secp256k1],
      specs: [:did_spec_registry, :security_vocab],
      contexts: ["https://w3id.org/security/suites/secp256k1-2019/v1"]
    },
    %{format: "EcdsaSecp256r1VerificationKey2019", curves: [:p256], specs: [], contexts: []},
    %{
      format: "Ed25519VerificationKey2018",
      curves: [:ed25519],
      specs: [:did_spec_registry, :security_vocab],
      contexts: ["https://w3id.org/security/suites/ed25519-2018/v1"]
    },
    %{
      format: "Ed25519VerificationKey2020",
      curves: [:ed25519],
      specs: [:security_vocab],
      contexts: ["https://w3id.org/security/suites/ed25519-2020/v1"]
    },
    %{
      format: "JsonWebKey2020",
      curves: [:p256, :secp256k1],
      specs: [:did_spec_registry, :security_vocab],
      contexts: ["https://w3id.org/security/suites/jws-2020/v1"]
    }
  ]

  @multicodecs %{
    ed25519: %{name: "ed25519-pub", tag: "key", code: 0xED, prefix: <<0xED, 0x01>>},
    secp256k1: %{name: "secp256k1-pub", tag: "key", code: 0xE7, prefix: <<0xE7, 0x01>>},
    p256: %{name: "p256-pub", tag: "key", code: 0x1200, prefix: <<0x80, 0x24>>},
    ed25519_priv: %{name: "ed25519-priv", tag: "key", code: 0x1300, prefix: <<0x80, 0x26>>},
    secp256k1_priv: %{name: "secp256k1-priv", tag: "key", code: 0x1301, prefix: <<0x81, 0x26>>},
    p256_priv: %{name: "p256-priv", tag: "key", code: 0x1306, prefix: <<0x86, 0x26>>}
  }

  @doc """
  Returns true if the key format is part of the base context we are using,
  that is, is either "JasonWebKey2020" or "Multikey".
  """
  def base_format?(public_key_format) do
    public_key_format in ["JsonWebKey2020", "Multikey"]
  end

  @doc """
  Given a curve name (atom) and the decoded public key bytes, returns a
  map with pertinent curve data, key formats and JSON LD-contexts.
  """
  def parse_public_key(:ed25519 = curve, key_bytes) do
    %{
      curve: curve,
      key_bytes: key_bytes,
      algo_key: {:eddsa, [key_bytes, curve]},
      jwk: CryptoUtils.Keys.make_public_key(key_bytes, curve, :jwk),
      jwt_alg: "ED25519",
      contexts: %{
        signature: {
          "Ed25519VerificationKey2018",
          "https://w3id.org/security#Ed25519VerificationKey2018"
        },
        encryption: {
          "Ed25519EncryptionKey2018",
          "https://w3id.org/security#Ed25519EncryptionKey2018"
        }
      }
    }
  end

  def parse_public_key(:p256 = curve, key_bytes) do
    case CryptoUtils.Curves.decompress_public_key_point(key_bytes, curve) do
      {:ok, uncompressed} ->
        %{
          curve: curve,
          key_bytes: key_bytes,
          algo_key: {:ecdsa, [uncompressed, :secp256r1]},
          jwk: CryptoUtils.Keys.make_public_key(uncompressed, curve, :jwk),
          jwt_alg: "ES256",
          contexts: %{
            signature: {
              "EcdsaSecp256r1VerificationKey2019",
              "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019"
            },
            encryption: {
              "EcdsaSecp256r1EncryptionKey2019",
              "https://w3id.org/security#EcdsaSecp256r1EncryptionKey2019"
            }
          }
        }

      _ ->
        raise CryptoUtils.Keys.EllipticCurveError, curve
    end
  end

  def parse_public_key(:secp256k1 = curve, key_bytes) do
    case CryptoUtils.Curves.decompress_public_key_point(key_bytes, curve) do
      {:ok, uncompressed} ->
        %{
          curve: curve,
          key_bytes: key_bytes,
          algo_key: {:ecdsa, [uncompressed, curve]},
          jwk: CryptoUtils.Keys.make_public_key(uncompressed, curve, :jwk),
          jwt_alg: "ES256K",
          contexts: %{
            signature: {
              "EcdsaSecp256k1VerificationKey2019",
              "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019"
            },
            encryption: {
              "EcdsaSecp256k1EncryptionKey2019",
              "https://w3id.org/security#EcdsaSecp256k1EncryptionKey2019"
            }
          }
        }

      _ ->
        raise CryptoUtils.Keys.EllipticCurveError, curve
    end
  end

  @doc """
  Utility to generate a multicodec prefix from integer code.
  """
  def code_to_prefix(number) do
    encode_varint(number) |> :erlang.list_to_binary()
  end

  @doc """
  Encodes a integer as a list of varint-encoded bytes.
  """
  def encode_varint(number) do
    encode_varint_loop(number, []) |> Enum.reverse()
  end

  defp encode_varint_loop(number, acc) do
    towrite = number &&& 0x7F
    number = number >>> 7

    if number != 0 do
      acc = [towrite ||| 0x80 | acc]
      encode_varint_loop(number, acc)
    else
      [towrite | acc]
    end
  end
end
