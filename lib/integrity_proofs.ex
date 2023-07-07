defmodule IntegrityProofs do
  @moduledoc """
  Documentation for `IntegrityProofs`.
  """

  require Record

  @valid_did_methods ["web", "key", "plc", "example"]
  @valid_proof_purposes ["assertionMethod"]
  @id_ed25519 {1, 3, 101, 112}
  @curve_params {:namedCurve, @id_ed25519}

  @doc """
  Erlang record for public key.

  @type ec_point() :: {
    ECPoint,
    point: binary()
  }
  """
  Record.defrecord(:ec_point, :ECPoint, point: "")

  @doc """
  Erlang record for private key.

  @type oid_tuple() :: {
    a: byte(),
    b: byte(),
    c: byte(),
    d: byte()
  }

  @type ec_private_key() :: {
    ECPrivateKey,
    version: integer(),
   private_key: binary(),
    parameters: {:ecParameters, {ECParameters, ...} |
              {:namedCurve, oid_tuple()} |
              {:implicitlyCA, 'NULL'},
   public_key: bitstring()
  }
  """
  Record.defrecord(:ec_private_key, :ECPrivateKey,
    version: 1,
    private_key: "",
    parameters: @curve_params,
    public_key: <<>>
  )

  defmodule ProofConfig do
    defstruct context: nil, type: nil, verification_method: nil, proof_purpose: nil
  end

  defmodule ProofTransformationError do
    defexception type: "undefined", cryptosuite: "undefined"

    def message(%{type: type, cryptosuite: cryptosuite}) do
      "Invalid transformation options: type = #{type}, cryptosuite = #{cryptosuite}"
    end
  end

  defmodule InvalidProofConfigurationError do
    defexception type: "undefined", cryptosuite: "undefined"

    def message(%{type: type, cryptosuite: cryptosuite}) do
      "Invalid proof configuration: type = #{type}, cryptosuite = #{cryptosuite}"
    end
  end

  defmodule InvalidProofDatetimeError do
    defexception created: nil

    def message(%{created: created}) do
      "Invalid proof datetime #{created}"
    end
  end

  defmodule InvalidVerificationMethodURLError do
    defexception url: nil

    def message(%{url: url}) do
      "Invalid verification method URL #{url}"
    end
  end

  defmodule InvalidControllerDocumentIdError do
    defexception id: nil

    def message(%{id: id}) do
      "Invalid controller document id #{id}"
    end
  end

  defmodule InvalidVerificationMethodError do
    defexception method: nil

    def message(%{method: method}) do
      "Invalid verification method #{inspect(method)}"
    end
  end

  defmodule InvalidProofPurposeForVerificationMethodError do
    defexception method: nil, purpose: nil

    def message(%{method: method, purpose: purpose}) do
      "Invalid proof purpose #{purpose} for verification method #{inspect(method)}"
    end
  end

  defmodule InvalidPublicKeyError do
    defexception multibase: nil, reason: nil

    def message(%{multibase: multibase, reason: reason}) do
      "Invalid public Multikey #{multibase}: #{reason}"
    end
  end

  @doc """
  Implements jcs-eddsa-2022 transformation of an untransformed
  document. § 3.2.

  1. If `options.type` is not set to the string "DataIntegrityProof" and
     options.cryptosuite is not set to the string "jcs-eddsa-2022" then
     a `ProofTransformationError` MUST be raised.
  2. Let canonicalDocument be the result of applying the JSON
      Canonicalization Scheme [RFC8785] to the unsecuredDocument.
  3. Return canonicalDocument as the transformed data document.
  """
  def transform_jcs_eddsa_2022!(untransformed_document, options \\ [])
      when is_map(untransformed_document) do
    type = Keyword.get(options, :type, "undefined")
    cryptosuite = Keyword.get(options, :cryptosuite, "undefined")

    if type != "DataIntegrityProof" && cryptosuite != "jcs-eddsa-2022" do
      raise IntegrityProofs.ProofTransformationError, type: type, cryptosuite: cryptosuite
    end

    Jcs.encode(untransformed_document)
  end

  @doc """
  Implements jcs-eddsa-2022 proof configuration. § 3.1.5 and § 3.2

  1. Let `proof_config` be an empty object.
  2. Set `proof_config.type` to `options.type`.
  3. If `options.cryptosuite` is set, set `proof_config.cryptosuite` to its value.
  4. If `options.type` is not set to  "DataIntegrityProof"  and
     `proof_config.cryptosuite` is not set to "jcs-eddsa-2022", an
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

    if type != "DataIntegrityProof" || cryptosuite != "jcs-eddsa-2022" do
      raise IntegrityProofs.InvalidProofConfigurationError, type: type, cryptosuite: cryptosuite
    end

    created = Keyword.get(options, :created)

    if !valid_datetime?(created) do
      raise IntegrityProofs.InvalidProofDatetimeError, created: created
    end

    proof_config = %{
      "@context": Map.fetch!(unsecured_document, "@context"),
      type: type,
      cryptosuite: cryptosuite,
      created: created,
      verificationMethod: verification_method,
      proofPurpose: proof_purpose
    }

    Jcs.encode(proof_config)
  end

  @doc """
  Implements jcs-eddsa-2022 hashing. § 3.1.4.

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
  Builds a "DataIntegrityProof" document for the "jcs-eddsa-2022"
  cryptosuite with the purpose "assertionMethod", and with other specified options.
  """
  def build_assertion_proof!(document, options) do
    transformed_document =
      IntegrityProofs.transform_jcs_eddsa_2022!(document,
        type: "DataIntegrityProof",
        cryptosuite: "jcs-eddsa-2022"
      )

    verification_method = Keyword.get(options, :verification_method)
    created = Keyword.get(options, :created)

    proof_config =
      IntegrityProofs.proof_configuration!(document,
        type: "DataIntegrityProof",
        cryptosuite: "jcs-eddsa-2022",
        created: created,
        verification_method: verification_method,
        proof_purpose: "assertionMethod"
      )

    hash_data = IntegrityProofs.hash(proof_config, transformed_document)
    proof_bytes = serialize_proof!(hash_data, options)
    proof_value = Multibase.encode!(proof_bytes, :base58_btc)

    Map.put(document, "proof", %{
      "type" => "DataIntegrityProof",
      "cryptosuite" => "jcs-eddsa-2022",
      "created" => created,
      "verificationMethod" => verification_method,
      "proofPurpose" => "assertionMethod",
      "proofValue" => proof_value
    })
  end

  @doc """
  Implements jcs-eddsa-2022 proof serialization
  § 3.1.6.

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
  Implements jcs-eddsa-2022 proof serialization
  § 3.1.7.

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
    vm_identifier = URI.parse(verification_method)
    vm_fragment = vm_identifier.fragment

    if !did_uri?(vm_identifier) && !http_uri?(vm_identifier) do
      raise InvalidVerificationMethodURLError, url: verification_method
    end

    controller_document_url = %URI{vm_identifier | fragment: nil} |> URI.to_string()
    controller_document = dereference_controller_document!(controller_document_url, options)
    document_id = Map.get(controller_document, "id")

    if document_id != controller_document_url do
      raise InvalidControllerDocumentIdError, id: document_id
    end

    verification_method =
      find_verification_method_fragment(controller_document, vm_fragment, options)

    if !valid_verification_method?(verification_method) do
      raise InvalidVerificationMethodError, method: verification_method
    end

    if !valid_purpose?(verification_method, vm_purpose) do
      raise InvalidProofPurposeForVerificationMethodError,
        method: verification_method,
        purpose: vm_purpose
    end

    verification_method
  end

  @doc """
  Verifies a proof.
  """
  def verify_proof_document!(proof_document, options) when is_map(proof_document) do
    {proof, document_to_verify} = Map.pop!(proof_document, "proof")
    {proof_value, raw_config} = Map.pop(proof, "proofValue")

    proof_config =
      IntegrityProofs.proof_configuration!(document_to_verify,
        type: raw_config["type"],
        cryptosuite: raw_config["cryptosuite"],
        created: raw_config["created"],
        verification_method: raw_config["verificationMethod"],
        proof_purpose: raw_config["proofPurpose"]
      )

    transformed_document =
      transform_jcs_eddsa_2022!(document_to_verify,
        type: "DataIntegrityProof",
        cryptosuite: "jcs-eddsa-2022"
      )

    hash_data = hash(proof_config, transformed_document)
    {:ok, {proof_bytes, :base58_btc}} = Multibase.codec_decode(proof_value)
    verify_proof!(hash_data, proof_bytes, Keyword.put(options, :proof, proof))
  end

  @doc """
  Retrieves the private key, from supplied data, a cache or
  via an HTTP request.

  See `make_ed25519_private_key/3` for details on the return
  formats specified in the `fmt` argument.
  """
  def retrieve_private_key!(options, fmt \\ :crypto_algo_key) do
    priv = Keyword.get(options, :private_key_bytes)
    pub = Keyword.get(options, :public_key_bytes)
    private_key_pem = Keyword.get(options, :private_key_pem)

    cond do
      !is_nil(priv) && !is_nil(pub) ->
        make_ed25519_private_key(pub, priv, fmt)

      !is_nil(private_key_pem) ->
        case decode_ed25519_pem(private_key_pem, :openssh_key_v1, fmt) do
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

  See `make_ed25519_public_key/2` for details on the return
  formats specified in the `fmt` argument.
  """
  def retrieve_public_key!(options, fmt \\ :crypto_algo_key) do
    proof = Keyword.get(options, :proof)
    cached_controller_document = Keyword.get(options, :cached_controller_document)
    pub = Keyword.get(options, :public_key_bytes)
    public_key_pem = Keyword.get(options, :public_key_pem)

    cond do
      is_map(proof) && is_map(cached_controller_document) ->
        verification_method = verification_method!(proof, options)
        {:ok, public_key} = IntegrityProofs.extract_multikey(verification_method, fmt)
        public_key

      is_binary(pub) ->
        make_ed25519_public_key(pub, fmt)

      is_binary(public_key_pem) ->
        case decode_ed25519_pem(public_key_pem, :public_key, fmt) do
          {:ok, public_key, _} -> public_key
          _ -> raise ArgumentError, IO.inspect(options)
        end

      true ->
        raise ArgumentError, IO.inspect(options)
    end
  end

  def dereference_controller_document!(_controller_document_url, options) do
    built_in = Keyword.get(options, :cached_controller_document)
    built_in
  end

  def find_verification_method_fragment(controller_document, vm_fragment, _options) do
    document_id = Map.fetch!(controller_document, "id")
    vm_url = document_id <> "#" <> vm_fragment

    Map.fetch!(controller_document, "verificationMethod")
    |> List.wrap()
    |> Enum.find(fn
      vm when is_map(vm) -> Map.fetch!(vm, "id") == vm_url
      _ -> false
    end)
  end

  @doc """
  Generates a new random public-private key pair. `fmt` determines the
  format of the keys returned. See `make_ed25519_public_key/2`
  and `make_ed25519_private_key/3` for details on the return
  formats.
  """
  def generate_ed25519_key_pair(fmt) do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)
    {make_ed25519_public_key(pub, fmt), make_ed25519_private_key(pub, priv, fmt)}
  end

  @doc """
  Returns a public key, from supplied data. `fmt` determines the
  format of the key returned.

  * `:public_key` returns a tuple `{{:ECPoint, pub}, {:namedCurve, {1, 3, 101, 112}}`.
  * `:public_key_ed` returns a tuple `{:ed_pub, :ed25519, pub}`.
  * `:crypto_algo_key` returns a tuple `{:eddsa, [pub, :ed25519]}`.
  * `:multikey` returns a btc58-encoded binary starting with "z6".
  * `:did_key` returns a binary starting with "did:key:".
  """
  def make_ed25519_public_key(pub, :public_key)
      when byte_size(pub) == 32 do
    {ec_point(point: pub), @curve_params}
  end

  def make_ed25519_public_key(pub, :public_key_ed)
      when byte_size(pub) == 32 do
    {:ed_pub, :ed25519, pub}
  end

  def make_ed25519_public_key(pub, :crypto_algo_key)
      when byte_size(pub) == 32 do
    {:eddsa, [pub, :ed25519]}
  end

  def make_ed25519_public_key(pub, :multikey)
      when byte_size(pub) == 32 do
    pub
    |> Multicodec.encode!("ed25519-pub")
    |> Multibase.encode!(:base58_btc)
  end

  def make_ed25519_public_key(pub, :did_key)
      when byte_size(pub) == 32 do
    multikey = make_ed25519_public_key(pub, :multikey)
    "did:key:" <> multikey
  end

  def make_ed25519_public_key(_, _), do: raise(ArgumentError)

  @doc """
  Returns a private key, from supplied data. `fmt` determines the
  format of the key returned.

  * `:public_key` returns a tuple `{:ECPrivateKey, 1, priv, {:namedCurve, {1, 3, 101, 112}}, pub}`.
  * `:public_key_ed` returns a tuple `{:ed_pri, :ed25519, pub, priv}`.
  * `:crypto_algo_key` returns a tuple `{:eddsa, [priv, :ed25519]}`.
  """
  def make_ed25519_private_key(pub, priv, :public_key)
      when byte_size(pub) == 32 and byte_size(priv) == 32 do
    ec_private_key(private_key: priv, public_key: pub)
  end

  def make_ed25519_private_key(pub, priv, :public_key_ed)
      when byte_size(pub) == 32 and byte_size(priv) == 32 do
    {:ed_pri, :ed25519, pub, priv}
  end

  def make_ed25519_private_key(pub, priv, :crypto_algo_key)
      when byte_size(pub) == 32 and byte_size(priv) == 32 do
    {:eddsa, [priv, :ed25519]}
  end

  def make_ed25519_private_key(_, _, _), do: raise(ArgumentError)

  @doc """
  Parses keys in files produced by the `ssh-keygen` command.

  For example, create a public-private key pair with:

  ```sh
  ssh-keygen -t ed25519 -C "bob@example.com" -f example
  ```

  Then use this function to decode the public key:

  ```elixir
  File.read!("example.pub") |> decode_ed25519_pem(:public_key)
  ```

  Or to decode the public key:

  ```elixir
  File.read!("example") |> decode_ed25519_pem(:openssh_key_v1)
  ```

  See `make_ed25519_public_key/2` and `make_ed25519_private_key/3` for
  details on the formats for the returned keys.
  """
  def decode_ed25519_pem(keys_pem, type \\ :openssh_key_v1, fmt \\ :crypto_algo_key)
      when is_binary(keys_pem) do
    case :ssh_file.decode(keys_pem, type) do
      decoded when is_list(decoded) ->
        public_key =
          Enum.find(decoded, fn
            {{{:ECPoint, _pub}, @curve_params}, attrs} when is_list(attrs) -> true
            _ -> false
          end)
          |> case do
            {{{:ECPoint, pub}, @curve_params}, _attrs} ->
              make_ed25519_public_key(pub, fmt)

            _ ->
              nil
          end

        private_key =
          Enum.find(decoded, fn
            {{:ECPrivateKey, 1, _priv, @curve_params, _pub, :asn1_NOVALUE}, attrs}
            when is_list(attrs) ->
              true

            _ ->
              false
          end)
          |> case do
            {{:ECPrivateKey, 1, priv, @curve_params, pub, :asn1_NOVALUE}, _attrs} ->
              make_ed25519_private_key(pub, priv, fmt)

            _ ->
              nil
          end

        {:ok, public_key, private_key}

      {:error, reason} ->
        IO.puts("Could not decode #{type}: #{reason}")
        {:error, reason}

      other ->
        IO.puts("Unexpected result decoding #{type}: #{inspect(other)}")
    end
  end

  @doc """
  Extracts the public key from a "Multikey" verification method.

  See `make_ed25519_public_key/2` for details on the formats for the
  returned key.
  """
  def extract_multikey(verification_method, fmt \\ :crypto_algo_key)

  def extract_multikey(
        %{"type" => "Multikey", "publicKeyMultibase" => multibase_value},
        fmt
      )
      when is_binary(multibase_value) do
    with {:ok, {pub, _codec, _multicodec_value}} <- decode_multikey(multibase_value) do
      {:ok, make_ed25519_public_key(pub, fmt)}
    end
  end

  def extract_multikey(_, _), do: {:error, "not a Multikey verification method"}

  @doc """
  Decodes the public key from a "Multikey" verification method's
  multibase value.

  Returns `{:ok, {raw_public_key_bytes, codec, multicodec_value}}` on success.
  """
  def decode_multikey(multibase_value) do
    with {:ok, {public_key, :base58_btc}} <- Multibase.codec_decode(multibase_value),
         {:ok, {raw_public_key_bytes, codec}} <- Multicodec.codec_decode(public_key),
         {:ok, <<multicodec_value::size(8), rest>>} <- Multicodec.prefix_for(codec) do
      {:ok, {raw_public_key_bytes, codec, multicodec_value}}
    end
  end

  @doc """
  Decodes the public key from a "Multikey" verification method's
  multibase value.

  Returns `{raw_public_key_bytes, codec, multicodec_value}` on success.
  Raises `InvalidPublicKeyError` on failure.
  """
  def decode_multikey!(multibase_value) do
    case decode_multikey(multibase_value) do
      {:ok, tuple} -> tuple
      {:error, reason} -> raise InvalidPublicKeyError, multibase: multibase_value, reason: reason
    end
  end

  def did_uri?(%URI{scheme: "did", host: nil, path: path})
      when is_binary(path) do
    case String.split(path, ":", parts: 2) do
      [did_method, did_value] -> did_method in @valid_did_methods && did_value != ""
      _ -> false
    end
  end

  def did_uri?(_), do: false

  def http_uri?(%URI{scheme: scheme, host: host, path: path}) do
    scheme in ["http", "https"] && !is_nil(host) && !is_nil(path)
  end

  def http_uri?(_), do: false

  defp valid_datetime?(dt) when is_binary(dt) do
    Regex.match?(~r/^\d\d\d\d-\d\d-\d\dT\d\d\:\d\d\:\d\dZ$/, dt)
  end

  defp valid_datetime?(_), do: false

  defp valid_verification_method?(verification_method) when is_map(verification_method) do
    case extract_multikey(verification_method) do
      {:ok, _key} -> true
      _ -> false
    end
  end

  defp valid_verification_method?(_), do: false

  defp valid_purpose?(_verification_method, purpose) do
    # TODO
    purpose in @valid_proof_purposes
  end
end
