defmodule IntegrityProofs.Did do
  @moduledoc """
  Functions to create and resolve DID documents.
  """

  @valid_did_methods ["web", "key", "plc", "example"]
  @known_signature_key_formats ["Multikey", "JsonWebKey2020", "Ed25519VerificationKey2020"]
  @known_encryption_key_formats ["Multikey", "JsonWebKey2020", "X25519KeyAgreementKey2020"]

  defmodule InvalidDidError do
    defexception did: nil

    def message(%{did: did}) do
      "Invalid DID #{did}"
    end
  end

  defmodule UnsupportedPublicKeyTypeError do
    defexception format: nil

    def message(%{format: format}) do
      "Unsupported public key type #{format}"
    end
  end

  @doc """
  Builds a DID document.

  1. Initialize document to an empty object.
  2. Using a colon (:) as the delimiter, split the `identifier` into its
     components: a `scheme`, a `method`, a `version`, and a `multibase_value`.
     If there are only three components set the `version` to the string
     value "1" and use the last value as the `multibase_value`.
  3. Check the validity of the input `identifier`. The `scheme` MUST be the
     value "did". The `method` MUST be the value "key". The `version` MUST be
     convertible to a positive integer value. The `multibase_value` MUST
     be a string and begin with the letter "z". If any of these requirements
     fail, an `InvalidDidError` MUST be raised.
  4. Initialize the `signature_verification_method` to the result of
     passing `identifier`, `multibase_value`, and `options` to § 3.1.2
     Signature Method Creation Algorithm.
  5. Set `document.id` to `identifier`. If `document.id` is not a valid DID,
     an `InvalidDidError` MUST be raised.
  6. Initialize the `verificationMethod` property in `document` to an
     array where the first value is the `signature_verification_method`.
  7. Initialize the `authentication`, `assertionMethod`,
    `capabilityInvocation`, and the `capabilityDelegation` properties
     in `document` to an array where the first item is the value of
     the `id` property in `signature_verification_method`.
  8.  If `options.enable_encryption_key_derivation` is set to `true`:
     8.1. Initialize the `encryption_verification_method` to the result of
          passing `identifier`, `multibase_value`, and `options` to § 3.1.5
          Encryption Method Creation Algorithm.
     8.2. Add the `encryption_verification_method` value to the
          `verification_method` array.
     8.3. Initialize the `keyAgreement` property in `document` to an array
          where the first item is the value of the `id` property in
          `encryption_verification_method`.
  11. Initialize the `@context` property in `document` to the result of
     passing `document` and `options` to the § 3.1.7 Context Creation Algorithm.
  12. Return document.
  """
  def build_did_document!(identifier, options \\ []) do
    parsed_did = parse_did!(identifier)

    %{"id" => sig_vm_id} =
      signature_verification_method = build_signature_method!(parsed_did, options)

    document = %{
      "@context" => [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/data-integrity/v1"
      ],
      "id" => identifier,
      "authentication" => [sig_vm_id],
      "assertionMethod" => [sig_vm_id],
      "capabilityInvocation" => [sig_vm_id],
      "capabilityDelegation" => [sig_vm_id]
    }

    if Keyword.get(options, :enable_encryption_key_derivation, false) do
      %{"id" => enc_vm_id} =
        encryption_verification_method = build_encryption_method!(parsed_did, options)

      document
      |> Map.put("verificationMethod", [
        signature_verification_method,
        encryption_verification_method
      ])
      |> Map.put("keyAgreement", [enc_vm_id])
    else
      Map.put(document, "verificationMethod", [signature_verification_method])
    end
  end

  @doc """
  Builds a verification method per § 3.1.2 Signature Method Creation
  Algorithm.

  1. Initialize `verification_method` to an empty object.
  2. Set `multicodec_value` and `raw_public_key_bytes` to the result of
     passing `multibase_value` and `options` to § 3.1.3 Decode Public
     Key Algorithm.
  3. Ensure the proper key length of `raw_public_key_bytes` based on the
     `multicodec_value`.
  4. Ensure the `raw_public_key_bytes` are a proper encoding of the public
     key type as specified by the `multicodec_value`. This validation
     is often done by a cryptographic library when importing the public
     key by, for example, ensuring that an Elliptic Curve public key
     is a specific coordinate that exists on the elliptic curve. If an
     invalid public key value is detected, an `InvalidPublicKeyError`
     MUST be raised.
  5. Set the `verification_method.id` value by concatenating `identifier`,
     a hash character ("#"), and the `multicodec_value`. If
     `verification_method.id` is not a valid DID URL, an `InvalidDidUrlError`
     MUST be raised.
  6. Set the `public_key_format` value to the `options.public_key_format` value.
  7. If `public_key_format` is not known to the implementation, an
     `UnsupportedPublicKeyTypeError` MUST be raised.
  8. If `options.enable_experimental_public_key_types` is set to `false`
     and `public_key_format` is not "Multikey", "JsonWebKey2020", or
     "Ed25519VerificationKey2020", an `InvalidPublicKeyTypeError` MUST
     be raised.
  9. Set `verification_method.type` to the `public_key_format` value.
  10. Set `verification_method.controller` to the `identifier` value. If
     `verification_method.controller` is not a valid DID, an
     `InvalidDidError` MUST be raised.
  11. If `public_key_format` is "Multikey" or "Ed25519VerificationKey2020",
     set the `verification_method.publicKeyMultibase` value to
     `multibase_value`. If `public_key_format` is "JsonWebKey2020", set the
     `verification_method.publicKeyJwk` value to the result of passing
     `multicodec_value` and `raw_public_key_bytes` to § 3.1.4 Encode JWK
     Algorithm.
  12. Return `verification_method`.
  """
  def build_signature_method!(
        %{identifier: identifier, multibase_value: multibase_value},
        options
      ) do
    public_key_format = Keyword.get(options, :public_key_format, "Multikey")
    # Not in standard
    fragment = Keyword.get(options, :signature_method_fragment, multibase_value)

    # The did:key Method draft here seems wrong.
    {_raw_public_key_bytes, %{codec: _codec, code: _multicodec_value, prefix: _prefix}} =
      IntegrityProofs.decode_multikey!(multibase_value)

    if !valid_signature_key_format?(public_key_format, options) do
      raise UnsupportedPublicKeyTypeError, format: public_key_format
    end

    %{
      "id" => identifier <> "#" <> fragment,
      "type" => public_key_format,
      "controller" => identifier,
      "publicKeyMultibase" => multibase_value
    }
  end

  @doc """
  Builds an encryption method per § 3.1.5 Encryption Method Creation
  Algorithm.

  1. Initialize `verification_method` to an empty object.
  2. Set `multicodec_value` and `raw_public_key_bytes` to the result
     of passing `multibase_value` and options to § 3.1.6 Derive
     Encryption Key Algorithm.
  3. Ensure the proper key length of `raw_public_key_bytes` based
     on the `multicodec_value` table.
  4. Create the `multibase_value` by concatenating the letter 'z'
     and the base58-btc encoding of the concatenation of the
     `multicodec_value` and the `raw_public_key_bytes`.
  5. Set the `verification_method.id` value by concatenating `identifier`,
     a hash character ("#"), and the `multibase_value`. If
     `verification_method.id` is not a valid DID URL, an
     `InvalidDidUrlError` MUST be raised.
  6. Set the `public_key_format` value to the `options.public_key_format`
     value.
  7. If `public_key_format` is not known to the implementation, an
     `UnsupportedPublicKeyTypeError` MUST be raised.
  8. If `options.enable_experimental_public_key_types` is set to `false`
     and `public_key_format` is not "Multikey", "JsonWebKey2020", or
     "X25519KeyAgreementKey2020", an `InvalidPublicKeyTypeError` MUST
     be raised.
  9. Set `verification_method.type` to the `public_key_format` value.
  10. Set `verification_method.controller` to `identifier`. If
     `verification_method`.controller is not a valid DID, an
     `InvalidDidError` MUST be raised.
  11. If `public_key_format` is "Multikey" or "X25519KeyAgreementKey2020",
     set the `verification_method.publicKeyMultibase` value to
     `multibase_value`. If `public_key_format` is "JsonWebKey2020",
     set the `verification_method.publicKeyJwk` value to the result
     of passing `multicodec_value` and `raw_public_key_bytes` to
     § 3.1.4 Encode JWK Algorithm.
  12. Return `verification_method`.
  """
  def build_encryption_method!(
        %{identifier: identifier, multibase_value: multibase_value},
        options
      ) do
    public_key_format = Keyword.get(options, :public_key_format, "Multikey")
    # Not in standard
    fragment = Keyword.get(options, :encryption_method_fragment, multibase_value)
    _decoded = IntegrityProofs.decode_multikey!(multibase_value)

    if !valid_encryption_key_format?(public_key_format, options) do
      raise UnsupportedPublicKeyTypeError, format: public_key_format
    end

    %{
      "id" => identifier <> "#" <> fragment,
      "type" => public_key_format,
      "controller" => identifier,
      "publicKeyMultibase" => multibase_value
    }
  end

  defp parse_did!(identifier) do
    parts = String.split(identifier, ":")

    parsed =
      case parts do
        ["did", method, multibase_value] ->
          %{method: method, version: "1", multibase_value: multibase_value}

        ["did", method, version, multibase_value] ->
          %{method: method, version: version, multibase_value: multibase_value}

        _ ->
          %{method: "invalid", version: "1", multibase_value: ""}
      end

    if parsed.method in @valid_did_methods && String.starts_with?(parsed.multibase_value, "z") do
      Map.put(parsed, :identifier, identifier)
    else
      raise InvalidDidError, did: identifier
    end
  end

  defp valid_signature_key_format?(format, options) do
    Keyword.get(options, :enable_experimental_key_types, false) ||
      format in @known_signature_key_formats
  end

  defp valid_encryption_key_format?(format, options) do
    Keyword.get(options, :enable_experimental_key_types, false) ||
      format in @known_encryption_key_formats
  end
end