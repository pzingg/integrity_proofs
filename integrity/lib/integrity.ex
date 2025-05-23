defmodule Integrity do
  @moduledoc """
  Utilities for creating and verifying data integrity.

  Section references in function descriptions refer to
  [Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
  """

  @valid_proof_purposes [
    "authentication",
    "assertionMethod",
    "keyAgreement",
    "capabilityDelegation",
    "capabilityInvocation"
  ]

  @supported_cryptosuites ["eddsa-jcs-2022", "jcs-eddsa-2022"]

  @typedoc """
  A Keyword option passed to any of the public functions
  defined by modules in this library.
  """
  @type integrity_option() ::
          {:type, String.t()}
          | {:cryptosuite, String.t()}
          | {:verification_method, String.t()}
          | {:proof_purpose, String.t()}
          | {:created, String.t()}
          | {:context, list()}
          | {:scheme, String.t()}
          | {:private_key_bytes, binary()}
          | {:public_key_bytes, binary()}
          | {:private_key_pem, String.t()}
          | {:public_key_pem, String.t()}
          | {:also_known_as, String.t() | [String.t()]}
          | {:multibase_value, String.t()}
          | {:public_key_format, String.t()}
          | {:signature_method_fragment, String.t()}
          | {:encryption_method_fragment, String.t()}
          | {:additional_vms, map()}
          | {:services, map()}
          | {:proof, map()}
          | {:cached_controller_document, map()}
          | {:enable_encryption_key_derivation, boolean()}
          | {:enable_experimental_key_types, boolean()}
          | {:expected_proof_purpose, String.t()}
          | {:acceptable_created_time_deviation, integer()}
          | {:dt_verified, DateTime.t()}

  @type integrity_options() :: [integrity_option()]

  defmodule ProofConfig do
    defstruct context: nil, type: nil, verification_method: nil, proof_purpose: nil
  end

  defmodule DidResolutionError do
    defexception [:did, :reason]

    @impl true
    def message(%{did: did, reason: reason}) do
      "Failed to resolve DID #{did}: #{reason}"
    end
  end

  defmodule ProofTransformationError do
    defexception type: "undefined", cryptosuite: "undefined"

    @impl true
    def message(%{type: type, cryptosuite: cryptosuite}) do
      "Invalid transformation options: type = #{type}, cryptosuite = #{cryptosuite}"
    end
  end

  defmodule InvalidProofConfigurationError do
    defexception type: "undefined", cryptosuite: "undefined"

    @impl true
    def message(%{type: type, cryptosuite: cryptosuite}) do
      "Invalid proof configuration: type = #{type}, cryptosuite = #{cryptosuite}"
    end
  end

  defmodule InvalidProofDatetimeError do
    defexception [:message]

    @impl true
    def exception(created) do
      %__MODULE__{message: "Invalid proof datetime #{inspect(created)}"}
    end
  end

  defmodule CreatedTimeDeviationError do
    defexception [:message]

    @impl true
    def exception(acceptable) do
      %__MODULE__{message: "proof created time deviated more than #{acceptable} seconds"}
    end
  end

  defmodule InvalidControllerDocumentError do
    defexception [:message]

    @impl true
    def exception(url) do
      %__MODULE__{message: "Invalid controller document; url is #{url}"}
    end
  end

  defmodule InvalidControllerDocumentIdError do
    defexception [:message]

    @impl true
    def exception(id) do
      %__MODULE__{message: "Invalid controller document id #{id}"}
    end
  end

  defmodule InvalidIntegrityProofError do
    defexception [:message]

    @impl true
    def exception(reason) do
      %__MODULE__{message: reason}
    end
  end

  defmodule InvalidProofPurposeForVerificationMethodError do
    defexception [:method, :purpose]

    @impl true
    def message(%{method: method, purpose: purpose}) do
      "Invalid proof purpose #{purpose} for verification method #{inspect(method)}"
    end
  end

  defmodule InvalidVerificationMethodError do
    defexception [:message]

    @impl true
    def exception(method) do
      %__MODULE__{message: "Invalid verification method #{inspect(method)}"}
    end
  end

  defmodule InvalidVerificationMethodURLError do
    defexception [:message]

    @impl true
    def exception(url) do
      %__MODULE__{message: "Invalid verification method URL #{url}"}
    end
  end

  defmodule MalformedProofError do
    defexception []

    @impl true
    def message(_) do
      "malformed proof"
    end
  end

  defmodule MismatchedProofPurposeError do
    defexception []

    @impl true
    def message(_) do
      "mismatched proof purpose"
    end
  end

  defmodule MissingIntegrityProofError do
    defexception []

    @impl true
    def message(_) do
      "no VerifiableIdentityStatement in attachment"
    end
  end

  @doc """
  Implements eddsa-jcs-2022 transformation of an untransformed
  document. § 3.2.

  1. If `options.type` is not set to the string "DataIntegrityProof" and
     options.cryptosuite is not set to the string "eddsa-jcs-2022" then
     a `ProofTransformationError` MUST be raised.
  2. Let canonicalDocument be the result of applying the JSON
      Canonicalization Scheme [RFC8785] to the unsecuredDocument.
  3. Return canonicalDocument as the transformed data document.
  """
  def transform_eddsa_jcs_2022!(untransformed_document, options \\ [])
      when is_map(untransformed_document) do
    type = Keyword.get(options, :type, "undefined")
    cryptosuite = Keyword.get(options, :cryptosuite, "undefined")

    if type != "DataIntegrityProof" || cryptosuite not in @supported_cryptosuites do
      raise ProofTransformationError, type: type, cryptosuite: cryptosuite
    end

    Jcs.encode(untransformed_document)
  end

  @doc """
  Implements eddsa-jcs-2022 proof configuration. § 3.1.5 and § 3.2.

  1. Let `proof_config` be an empty object.
  2. Set `proof_config.type` to `options.type`.
  3. If `options.cryptosuite` is set, set `proof_config.cryptosuite` to its value.
  4. If `options.type` is not set to  "DataIntegrityProof"  and
     `proof_config.cryptosuite` is not set to "eddsa-jcs-2022", an
     `InvalidProofConfigurationError` MUST be raised.
  5. Set `proof_config.created` to `options.created`. If the value is not a
     valid [XMLSCHEMA11-2] datetime, an `InvalidProofDatetimeError`
     MUST be raised.
  6. Set `proof_config.verification_method` to `options.verification_method`.
  7. Set `proof_config.proof_purpose` to `options.proof_purpose`.
  8. Set `proof_config.@context` to `unsecured_document.@context`
  9. Let `canonical_proof_config` be the result of applying the JSON
     Canonicalization Scheme [RFC8785] to the `proof_config`.
  10. Return `canonical_proof_config`.
  """
  def proof_configuration!(unsecured_document, options \\ []) when is_map(unsecured_document) do
    type = Keyword.get(options, :type, "undefined")
    cryptosuite = Keyword.get(options, :cryptosuite, "undefined")
    verification_method = Keyword.get(options, :verification_method, "undefined")
    proof_purpose = Keyword.get(options, :proof_purpose, "undefined")

    if type != "DataIntegrityProof" || cryptosuite not in @supported_cryptosuites do
      raise InvalidProofConfigurationError, type: type, cryptosuite: cryptosuite
    end

    created = Keyword.get(options, :created)

    if !CryptoUtils.valid_datetime?(created) do
      raise InvalidProofDatetimeError, created
    end

    proof_config = %{
      type: type,
      cryptosuite: cryptosuite,
      created: CryptoUtils.format_datetime(created),
      verificationMethod: verification_method,
      proofPurpose: proof_purpose
    }

    context = Keyword.get(options, :context) || Map.get(unsecured_document, "@context")

    proof_config =
      if context do
        Map.put(proof_config, "@context", context)
      else
        proof_config
      end

    Jcs.encode(proof_config)
  end

  @doc """
  Implements eddsa-jcs-2022 hashing. § 3.1.4.

  1. Let `transformed_document_hash` be the result of applying the SHA-256
     (SHA-2 with 256-bit output) cryptographic hashing algorithm
     [RFC6234] to the transformedDocument. `transformed_document_hash` will
     be exactly 32 bytes in size.
  2. Let `proof_config_hash` be the result of applying the SHA-256 (SHA-2
     with 256-bit output) cryptographic hashing algorithm [RFC6234]
     to the `canonical_proof_config`. `proof_config_hash` will be exactly 32
     bytes in size.
  3. Let hashData be the result of joining `proof_config_hash` (the first
     hash) with `transformed_document_hash` (the second hash).
  4. Return hashData as the hash data.
  """
  def hash(canonical_proof_config, transformed_document)
      when is_binary(canonical_proof_config) and is_binary(transformed_document) do
    proof_config_hash = :crypto.hash(:sha256, canonical_proof_config)
    transformed_document_hash = :crypto.hash(:sha256, transformed_document)
    proof_config_hash <> transformed_document_hash
  end

  @doc """
  Builds a "DataIntegrityProof" document for the "eddsa-jcs-2022"
  cryptosuite with the purpose "assertionMethod", and with other specified options.
  """
  def build_assertion_proof!(document, options) do
    verification_method = Keyword.fetch!(options, :verification_method)
    created = Keyword.fetch!(options, :created)
    cryptosuite = Keyword.fetch!(options, :cryptosuite)

    # Support deprecated "jcs-eddsa-2022"
    transformed_document =
      if cryptosuite in @supported_cryptosuites do
        transform_eddsa_jcs_2022!(document,
          type: "DataIntegrityProof",
          cryptosuite: cryptosuite
        )
      else
        raise ArgumentError, "Cryptosuite #{cryptosuite} not supported"
      end

    options =
      Keyword.merge(options,
        type: "DataIntegrityProof",
        cryptosuite: cryptosuite,
        proof_purpose: "assertionMethod"
      )

    proof_config = proof_configuration!(document, options)
    hash_data = hash(proof_config, transformed_document)
    proof_bytes = serialize_proof!(hash_data, options)
    proof_value = Multibase.encode!(proof_bytes, :base58_btc)

    Map.put(document, "proof", %{
      "type" => "DataIntegrityProof",
      "cryptosuite" => cryptosuite,
      "created" => created,
      "verificationMethod" => verification_method,
      "proofPurpose" => "assertionMethod",
      "proofValue" => proof_value
    })
  end

  @doc """
  Implements eddsa-jcs-2022 proof serialization. § 3.1.6.

  1. Let `private_key_bytes` be the result of retrieving the private key
     bytes associated with the `options.verification_method` value as
     described in the Data Integrity [VC-DATA-INTEGRITY] specification,
     § 4: Retrieving Cryptographic Material.
  2. Let `proof_bytes` be the result of applying the Edwards-Curve Digital
     Signature Algorithm (EdDSA) [RFC8032], using the Ed25519 variant
     (Pure EdDSA), with `hash_data` as the data to be signed using the
     private key specified by `private_key_bytes`. `proof_bytes` will be
     exactly 64 bytes in size.
  3. Return `proof_bytes` as the digital proof.
  """
  def serialize_proof!(hash_data, options \\ []) when is_binary(hash_data) do
    # :public_key.sign(hash_data, :none, private_key, [])
    {algorithm, crypto_key} = retrieve_private_key!(options, :crypto_algo_key)
    :crypto.sign(algorithm, :none, hash_data, crypto_key, [])
  end

  @doc """
  Implements eddsa-jcs-2022 proof verification, § 3.1.7.

  1. Let `public_key_bytes` be the result of retrieving the public key
     bytes associated with the `options.verification_method` value as
     described in the Data Integrity [VC-DATA-INTEGRITY] specification,
     § 4: Retrieving Cryptographic Material.
  2. Let `verification_result` be the result of applying the verification
     algorithm for the Edwards-Curve Digital Signature Algorithm (EdDSA)
     [RFC8032], using the Ed25519 variant (Pure EdDSA), with `hash_data`
     as the data to be verified against the `proof_bytes` using the public
     key specified by `public_key_bytes`.
  3. Return `verification_result` as the verification result.
  """
  def verify_proof!(hash_data, proof_bytes, options \\ []) do
    # :public_key.verify(hash_data, :none, proof_bytes, public_key, [])
    {algorithm, crypto_key} = retrieve_public_key!(options, :crypto_algo_key)
    :crypto.verify(algorithm, :none, hash_data, proof_bytes, crypto_key, [])
  end

  @doc """
  Retrieve a verification method. § 4.3.

  Required inputs are a data integrity proof (`proof`) and a set of
  dereferencing options (`options`).

  1. Let `vm_identifier` be set to `proof.verificationMethod`.
  2. Let `vm_purpose` be set to `proof.proofPurpose`.
  3. If `vm_identifier` is not a valid URL, an
     `InvalidVerificationMethodURLError` MUST be raised.
  4. Let `controller_document_url` be the result of parsing `vm_identifier`
     according to the rules of the URL scheme and extracting the primary
     resource identifier (without the fragment identifier).
  5. Let `vm_fragment` be the result of parsing `vm_identifier` according
     to the rules of the URL scheme and extracting the secondary resource
     identifier (the fragment identifier).
  6. Let `controller_document` be the result of dereferencing
     `controller_document_url`, according to the rules of the URL scheme
     and using the supplied options.
  7. If `controller_document.id` does not match the `controller_document_url`,
     an `InvalidControllerDocumentIdError` MUST be raised.
  8. If `controller_document` is not a valid controller document, an
     `InvalidControllerDocumentError` MUST be raised.
  9. Let `verification_method` be the result of dereferencing the
     `vm_fragment` from the `controller_document` according to the rules
     of the media type of the `controller_document`.
  10. If `verification_method` is not a valid verification method, an
     `InvalidVerificationMethodError` MUST be raised.
  11. If `verification_method` is not associated with the array of
      `vm_purpose`s in the `controller_document`, either by reference (URL)
      or by value (object), an `InvalidProofPurposeForVerificationMethodError`
      MUST be raised.
  12. Return `verification_method` as the verification method.
  """
  def verification_method!(
        %{
          "type" => "DataIntegrityProof",
          "cryptosuite" => _cryptosuite,
          "created" => _created,
          "verificationMethod" => verification_method,
          "proofPurpose" => vm_purpose,
          "proofValue" => _value
        },
        options
      ) do
    if !valid_purpose?(verification_method, vm_purpose) do
      raise InvalidProofPurposeForVerificationMethodError,
        method: verification_method,
        purpose: vm_purpose
    end

    vm_identifier = URI.parse(verification_method)
    vm_fragment = vm_identifier.fragment

    if !(CryptoUtils.did_uri?(vm_identifier) || CryptoUtils.http_uri?(vm_identifier)) do
      raise InvalidVerificationMethodURLError, verification_method
    end

    controller_document_url = %URI{vm_identifier | fragment: nil, query: nil} |> URI.to_string()
    controller_document = dereference_controller_document!(controller_document_url, options)

    if !Map.has_key?(controller_document, "id") do
      raise InvalidControllerDocumentError, controller_document_url
    end

    document_id = Map.get(controller_document, "id")

    if document_id != controller_document_url do
      raise InvalidControllerDocumentIdError, document_id
    end

    verification_method =
      find_verification_method_fragment(controller_document, vm_fragment, options)

    if !valid_verification_method?(verification_method) do
      raise InvalidVerificationMethodError, verification_method
    end

    verification_method
  end

  @doc """
  Verifies a proof document, e.g. an object (map) with a `proof` property that
  has `type`, `cryptosuite`, `created`, `verificationMethod`, `proofPurpose`
  and `proofValue` properties. § 4.2.

  Returns `true` if the proof can be verified.

  May raise errors if the proof is not in a valid format.

  1. Let `proof` be set to `securedDocument.proof`.
  2. If the `proof.type`, `proof.verificationMethod`, or `proof.proofPurpose`
     values are not set, a `MalformedProofError` MUST be raised.
  3. If the cryptographic suite requires the `proof.created` value, and
     it is not set, a `MalformedProofError` MUST be raised.
  4. If the `proof.proofPurpose` value does not match
     option `expected_proof_purpose`, a `MismatchedProofPurposeError`
     MUST be raised.
  5. Let `unsecuredDocument` be a copy of `securedDocument` with the
     proof value removed.
  6. Let `transformedData` be the result of transforming the
     `unsecuredDocument` according to a transformation algorithm associated
     with the cryptographic suite specified in proof and the options
     parameters provided as inputs to the algorithm. The type of
     cryptographic suite is specified by the `proof.type` value and MAY
     be further described by cryptographic suite-specific properties
     expressed in proof.
  7. Let `hashData` be the result of hashing the `transformedData` according
     to a hashing algorithm associated with the cryptographic suite
     specified in the proof and options parameters provided as inputs to
     the algorithm.
  8. Let `proof_verified?` be the result of running the proof verification
     algorithm associated with the cryptographic suite with the `hashData`
     and options parameters provided as inputs to the algorithm.
  9. If the `proof.created` is set and it deviates more than
     options `acceptable_created_time_deviation` seconds, a
     `CreatedTimeDeviationError` MUST be raised.
  10. If `options.domain` is set and it does not match `proof.domain`,
     an `InvalidDomainError` MUST be raised.
  11. If `options.challenge` is set and it does not match `proof.challenge`,
     an `InvalidChallengeError` MUST be raised.
  12. Return `proof_verified?` as the verification result.
  """
  def verify_proof_document!(proof_document, options) when is_map(proof_document) do
    expected_proof_purpose = Keyword.fetch!(options, :expected_proof_purpose)

    acceptable_created_time_deviation =
      Keyword.get(options, :acceptable_created_time_deviation, 0)

    dt_verified = Keyword.get(options, :dt_verified, NaiveDateTime.utc_now())

    {proof, document_to_verify} = Map.pop!(proof_document, "proof")

    with %{
           "type" => type,
           "cryptosuite" => cryptosuite,
           "created" => created,
           "verificationMethod" => verification_method,
           "proofPurpose" => proof_purpose,
           "proofValue" => proof_value
         } <- proof,
         true <-
           is_binary(type) && is_binary(cryptosuite) && is_binary(created) &&
             is_binary(verification_method) && is_binary(proof_purpose) && is_binary(proof_value),
         {:ok, dt_created, 0} <- DateTime.from_iso8601(created) do
      if proof_purpose != expected_proof_purpose do
        raise MismatchedProofPurposeError
      end

      options =
        Keyword.merge(options,
          type: type,
          cryptosuite: cryptosuite,
          created: created,
          verification_method: verification_method,
          proof_purpose: proof_purpose
        )

      proof_config = proof_configuration!(document_to_verify, options)

      transformed_document =
        transform_eddsa_jcs_2022!(document_to_verify,
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022"
        )

      hash_data = hash(proof_config, transformed_document)
      {:ok, {proof_bytes, :base58_btc}} = Multibase.codec_decode(proof_value)

      proof_verified? = verify_proof!(hash_data, proof_bytes, Keyword.put(options, :proof, proof))

      if acceptable_created_time_deviation > 0 do
        deviation = DateTime.diff(dt_verified, dt_created) |> abs()

        if deviation > acceptable_created_time_deviation do
          raise CreatedTimeDeviationError, acceptable_created_time_deviation
        end
      end

      proof_verified?
    else
      _ ->
        raise MalformedProofError
    end
  end

  @doc """
  Retrieves the private key, from supplied data, a cache or
  via an HTTP request.

  See `CryptoUtils.Keys.make_private_key/3` for details on the return
  formats specified in the `fmt` argument.
  """
  def retrieve_private_key!(options, fmt \\ :crypto_algo_key) do
    priv = Keyword.get(options, :private_key_bytes)
    pub = Keyword.get(options, :public_key_bytes)
    curve = Keyword.get(options, :curve, :ed25519)
    private_key_pem = Keyword.get(options, :private_key_pem)

    cond do
      !is_nil(priv) && !is_nil(pub) ->
        CryptoUtils.Keys.make_private_key({pub, priv}, curve, fmt)

      !is_nil(private_key_pem) ->
        case CryptoUtils.Keys.decode_pem_ssh_file(private_key_pem, :openssh_key_v1, fmt) do
          {:ok, _, private_key} -> private_key
          _ -> raise ArgumentError, IO.inspect(options)
        end

      true ->
        raise ArgumentError, IO.inspect(options)
    end
  end

  @doc """
  Retrieves the public key, from supplied data, a cache or
  via an HTTP request.

  See `CryptoUtils.Keys.make_public_key/3` for details on the return
  formats specified in the `fmt` argument.
  """
  def retrieve_public_key!(options, fmt \\ :crypto_algo_key) do
    proof = Keyword.get(options, :proof)
    verification_method = Keyword.get(options, :verification_method)
    cached_controller_document = Keyword.get(options, :cached_controller_document)
    key_bytes = Keyword.get(options, :public_key_bytes)
    curve = Keyword.get(options, :curve, :ed25519)
    public_key_pem = Keyword.get(options, :public_key_pem)

    cond do
      is_binary(verification_method) && String.starts_with?(verification_method, "did:key:") ->
        vm_identifier = URI.parse(verification_method)
        verification_method = %URI{vm_identifier | fragment: nil, query: nil} |> to_string()
        parsed_key = CryptoUtils.Did.parse_did!(verification_method)

        if fmt == :crypto_algo_key do
          parsed_key.algo_key
        else
          CryptoUtils.Keys.make_public_key(parsed_key.key_bytes, parsed_key.curve, fmt)
        end

      is_binary(key_bytes) ->
        CryptoUtils.Keys.make_public_key(key_bytes, curve, fmt)

      is_binary(public_key_pem) ->
        case CryptoUtils.Keys.decode_pem_ssh_file(public_key_pem, :public_key, fmt) do
          {:ok, public_key, _} -> public_key
          _ -> raise ArgumentError, IO.inspect(options)
        end

      is_map(proof) && is_map(cached_controller_document) ->
        verification_method = verification_method!(proof, options)
        {:ok, public_key} = CryptoUtils.Keys.extract_multikey(verification_method, fmt)
        public_key

      true ->
        raise ArgumentError, IO.inspect(options)
    end
  end

  defp dereference_controller_document!(_controller_document_url, options) do
    Keyword.get(options, :cached_controller_document, %{})
  end

  defp find_verification_method_fragment(controller_document, vm_fragment, _options) do
    document_id = Map.fetch!(controller_document, "id")
    vm_url = document_id <> "#" <> vm_fragment

    Map.fetch!(controller_document, "verificationMethod")
    |> List.wrap()
    |> Enum.find(fn
      vm when is_map(vm) -> Map.get(vm, "id", "") == vm_url
      _ -> false
    end)
  end

  defp valid_verification_method?(verification_method) when is_map(verification_method) do
    case CryptoUtils.Keys.extract_multikey(verification_method, :crypto_algo_key) do
      {:ok, _key} -> true
      _ -> false
    end
  end

  defp valid_verification_method?(_), do: false

  defp valid_purpose?(_verification_method, purpose) do
    purpose in @valid_proof_purposes
  end
end
