defmodule CryptoUtils.Did do
  @moduledoc """
  Basic DID handling.
  """

  alias CryptoUtils.Cid
  alias CryptoUtils.Plc.{CreateOperation, CreateParams, UpdateOperation}

  defmodule EllipticCurveError do
    defexception [:message]

    @impl true
    def exception(curve) do
      %__MODULE__{message: "Point not on elliptic curve #{curve}"}
    end
  end

  defmodule GenesisHashError do
    defexception [:message]

    @impl true
    def exception(expected_did) do
      %__MODULE__{message: "expected did #{expected_did} for genesis operation"}
    end
  end

  defmodule ImproperOperationError do
    defexception [:op, :message]

    @impl true
    def message(%{op: op, message: message}) do
      "#{message}, op: #{inspect(op)}"
    end
  end

  defmodule InvalidDidError do
    defexception [:message]

    @impl true
    def exception(did) do
      %__MODULE__{message: "Invalid DID #{did}"}
    end
  end

  defmodule InvalidSignatureError do
    defexception [:message]

    @impl true
    def exception(_op) do
      %__MODULE__{message: "invalid signature"}
    end
  end

  defmodule LateRecoveryError do
    defexception [:message]

    @impl true
    def exception(lapsed) do
      %__MODULE__{message: "72 hour recovery period exceeded: #{lapsed} seconds"}
    end
  end

  defmodule MisorderedOperationError do
    defexception [:message]

    @impl true
    def exception(reason) do
      %__MODULE__{message: "misordered plc operation: #{reason}"}
    end
  end

  defmodule MissingSignatureError do
    defexception [:message]

    @impl true
    def exception(_op) do
      %__MODULE__{message: "operation is missing signature"}
    end
  end

  defmodule UnexpectedDidMethodError do
    defexception [:message]

    @impl true
    def exception(method) do
      %__MODULE__{message: "Unexpected DID method #{method}"}
    end
  end

  defmodule UnsupportedKeyError do
    defexception [:message]

    @impl true
    def exception(key) do
      %__MODULE__{message: "Unsupported key #{key}"}
    end
  end

  defmodule UnsupportedPublicKeyCodecError do
    defexception [:message]

    @impl true
    def exception(prefix) do
      %__MODULE__{message: "Unsupported public key codec #{prefix}"}
    end
  end

  defmodule UnsupportedPublicKeyTypeError do
    defexception [:message]

    @impl true
    def exception(format) do
      %__MODULE__{message: "Unsupported public key type #{format}"}
    end
  end

  @valid_did_methods ["web", "key", "plc", "example"]
  @known_signature_key_formats ["Multikey", "JsonWebKey2020", "Ed25519VerificationKey2020"]
  @known_encryption_key_formats ["Multikey", "JsonWebKey2020", "X25519KeyAgreementKey2020"]

  # @ed25519_code 0xED
  @ed25519_prefix <<0xED, 0x01>>
  @ed25519_jwt_alg "ED25519"

  # @p256_code 0x1200
  @p256_prefix <<0x80, 0x24>>
  @p256_jwt_alg "ES256"

  # @secp256k1_code 0xE7
  @secp256k1_prefix <<0xE7, 0x01>>
  @secp256k1_jwt_alg "ES256K"

  @base_context [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/data-integrity/v1"
  ]

  @doc """
  Resolve the URL for a did:web identifier.

  The method specific identifier MUST match the common name used in
  the SSL/TLS certificate, and it MUST NOT include IP addresses.
  A port MAY be included and the colon MUST be percent encoded to
  prevent a conflict with paths. Directories and subdirectories MAY
  optionally be included, delimited by colons rather than slashes.

  web-did = "did:web:" domain-name
  web-did = "did:web:" domain-name * (":" path)
  """
  def did_web_uri(identifier, options \\ []) do
    if String.starts_with?(identifier, "did:web:") do
      parsed_did = CryptoUtils.Did.parse_did!(identifier, options)

      {:ok,
       %URI{
         scheme: parsed_did.scheme,
         host: parsed_did.host,
         port: parsed_did.port,
         path: parsed_did.path
       }}
    else
      {:error, "not a did:web identifier"}
    end
  end

  @doc """
  Parse a did
  """
  def parse_did!(identifier, options \\ []) do
    parts = String.split(identifier, ":", parts: 3)

    if Enum.count(parts) != 3 || hd(parts) != "did" do
      raise InvalidDidError, identifier
    end

    [_, method, method_specific_id] = parts
    expected_did_method = Keyword.get(options, :expected_did_method)

    if !is_nil(expected_did_method) && expected_did_method != method do
      raise UnexpectedDidMethodError, method
    end

    parsed = %{
      did_string: identifier,
      method: String.to_existing_atom(method),
      method_specific_id: method_specific_id
    }

    case method do
      "key" ->
        validate_did!(:key, parsed, String.split(method_specific_id, ":"), options)

      "web" ->
        validate_did!(:web, parsed, String.split(method_specific_id, ":"), options)

      _ ->
        raise InvalidDidError, identifier
    end
  end

  defp validate_did!(:key, %{did_string: identifier} = parsed, [multibase_value], _) do
    if String.starts_with?(multibase_value, "z") do
      Map.merge(
        parsed,
        %{
          version: "1",
          multibase_value: multibase_value
        }
      )
    else
      raise InvalidDidError, identifier
    end
  end

  defp validate_did!(:key, %{did_string: identifier} = parsed, [version, multibase_value], _) do
    if String.starts_with?(multibase_value, "z") do
      Map.merge(
        parsed,
        %{
          version: version,
          multibase_value: multibase_value
        }
      )
    else
      raise InvalidDidError, identifier
    end
  end

  defp validate_did!(:web, %{did_string: identifier} = parsed, [host_port | path_parts], options) do
    path =
      if Enum.all?(path_parts, fn part ->
           part != "" && is_nil(Regex.run(~r/\s/, part))
         end) do
        case Enum.join(path_parts, "/") do
          "" -> "/.well-known/did.json"
          p -> "/" <> p <> "/did.json"
        end
      else
        nil
      end

    {host, port, path} =
      URI.decode(host_port)
      |> String.split(":", parts: 2)
      |> case do
        [host] ->
          {host, nil, path}

        [host, port] ->
          case Integer.parse(port) do
            {p, ""} -> {host, p, path}
            _ -> {host, 0, path}
          end
      end

    cond do
      is_nil(path) ->
        raise InvalidDidError, identifier

      is_integer(port) && (port == 0 || port > 65535) ->
        raise InvalidDidError, identifier

      true ->
        scheme = Keyword.get(options, :scheme, "https")

        port =
          case {scheme, port} do
            {"http", 80} -> nil
            {"https", 443} -> nil
            {_, p} -> p
          end

        Map.merge(parsed, %{scheme: scheme, host: host, port: port, path: path})
    end
  end

  defp validate_did!(_, %{did_string: identifier}, _, _) do
    raise InvalidDidError, identifier
  end

  @doc """
  Builds a DID document per § 3.1.1 Document Creation Algorithm.

  1. Initialize document to an empty object.
  2. Using a colon (":") as the delimiter, split the `identifier` into its
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
     Signature Method Creatio
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/data-integrity/v1"nd the `capabilityDelegation` properties
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
  def format_did_document!(identifier, options \\ []) do
    parsed_did = CryptoUtils.Did.parse_did!(identifier)

    %{
      context: sig_vm_context,
      verification_method: %{"id" => sig_vm_id} = signature_verification_method
    } = build_signature_method!(parsed_did, options)

    document = %{
      "@context" => @base_context ++ [sig_vm_context],
      "id" => identifier,
      "authentication" => [sig_vm_id],
      "assertionMethod" => [sig_vm_id],
      "capabilityInvocation" => [sig_vm_id],
      "capabilityDelegation" => [sig_vm_id]
    }

    document =
      if Keyword.get(options, :enable_encryption_key_derivation, false) do
        %{
          context: _context,
          verification_method: %{"id" => enc_vm_id} = encryption_verification_method
        } = build_encryption_method!(parsed_did, options)

        document
        |> Map.put("verificationMethod", [
          signature_verification_method,
          encryption_verification_method
        ])
        |> Map.put("keyAgreement", [enc_vm_id])
      else
        Map.put(document, "verificationMethod", [signature_verification_method])
      end

    Encryption

    case Keyword.get(options, :also_known_as) do
      nil -> document
      also_known_as -> Map.put(document, "alsoKnownAs", also_known_as)
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
        %{method: :key, did_string: identifier, multibase_value: multibase_value},
        options
      ) do
    do_signature_method(identifier, multibase_value, options)
  end

  def build_signature_method!(%{did_string: identifier}, options) do
    multibase_value = Keyword.fetch!(options, :multibase_value)
    do_signature_method(identifier, multibase_value, options)
  end

  defp do_signature_method(identifier, multibase_value, options) do
    # Not in standard
    fragment = Keyword.get(options, :signature_method_fragment, multibase_value)
    # The did:key Method draft here seems wrong.
    {_raw_public_key_bytes, curve} = CryptoUtils.Keys.decode_multikey!(multibase_value)

    {type, context} = type_and_context_for_curve(curve, :verification)
    public_key_format = Keyword.get(options, :public_key_format, type)

    if !valid_signature_key_format?(public_key_format, options) do
      raise UnsupportedPublicKeyTypeError, public_key_format
    end

    %{
      context: context,
      verification_method: %{
        "id" => identifier <> "#" <> fragment,
        "type" => public_key_format,
        "controller" => identifier,
        "publicKeyMultibase" => multibase_value
      }
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
        %{did_string: identifier, multibase_value: multibase_value},
        options
      ) do
    # Not in standard
    fragment = Keyword.get(options, :encryption_method_fragment, multibase_value)
    {_raw_public_key_bytes, curve} = CryptoUtils.Keys.decode_multikey!(multibase_value)

    {type, context} = type_and_context_for_curve(curve, :encryption)
    public_key_format = Keyword.get(options, :public_key_format, type)

    if !valid_encryption_key_format?(public_key_format, options) do
      raise UnsupportedPublicKeyTypeError, public_key_format
    end

    %{
      context: context,
      verification_method: %{
        "id" => identifier <> "#" <> fragment,
        "type" => public_key_format,
        "controller" => identifier,
        "publicKeyMultibase" => multibase_value
      }
    }
  end

  @doc """
  Returns a list of the DID methods understood by this module, as strings.
  """
  def valid_did_methods(), do: @valid_did_methods

  defp valid_signature_key_format?(format, options) do
    Keyword.get(options, :enable_experimental_key_types, false) ||
      format in @known_signature_key_formats
  end

  defp valid_encryption_key_format?(format, options) do
    Keyword.get(options, :enable_experimental_key_types, false) ||
      format in @known_encryption_key_formats
  end

  @doc """
  Create a DID document per the AT Protocol.
  """
  def format_did_plc_document(%{"did" => did, "alsoKnownAs" => also_known_as} = data)
      when is_binary(did) do
    {context, verification_methods} =
      Map.get(data, "verificationMethods", %{})
      |> Enum.reduce(
        {@base_context, []},
        fn {key_id, key}, {ctx, vms} ->
          %{context: context, type: type, public_key_multibase: public_key_multibase} =
            context_and_key_for_did!(key)

          ctx =
            if context in [ctx] do
              ctx
            else
              [context | ctx]
            end

          vms = [
            %{
              "id" => key_id,
              "type" => type,
              "controller" => did,
              "publicKeyMultibase" => public_key_multibase
            }
            | vms
          ]

          {ctx, vms}
        end
      )

    services =
      Map.get(data, "services", %{})
      |> Enum.map(fn {service_id, %{"type" => type, "endpoint" => endpoint}} ->
        %{"id" => service_id, "type" => type, "serviceEndpoint" => endpoint}
      end)

    %{
      "@context" => Enum.reverse(context),
      "id" => did,
      "alsoKnownAs" => also_known_as,
      "verificationMethod" => verification_methods,
      "service" => services
    }
  end

  def context_and_key_for_did!(did) do
    %{curve: curve, key_bytes: key_bytes} = parse_did_key!(did)
    {type, context} = type_and_context_for_curve(curve, :verification)

    %{
      context: context,
      type: type,
      public_key_multibase: Multibase.encode!(key_bytes, :base58_btc)
    }
  end

  def parse_did_key!(did) do
    %{multibase_value: multibase_value} =
      CryptoUtils.Did.parse_did!(did, expected_did_method: "key")

    prefixed_bytes = Multibase.decode!(multibase_value)
    <<prefix::binary-size(2), key_bytes::binary>> = prefixed_bytes

    case prefix do
      @ed25519_prefix ->
        %{
          curve: :ed25519,
          jwt_alg: @ed25519_jwt_alg,
          key_bytes: prefixed_bytes,
          algo_key: {:eddsa, [key_bytes, :ed25519]}
        }

      @p256_prefix ->
        case CryptoUtils.Curves.decompress_public_key_point(key_bytes, :p256) do
          {:ok, uncompressed} ->
            %{
              curve: :p256,
              jwt_alg: @p256_jwt_alg,
              key_bytes: prefixed_bytes,
              algo_key: {:ecdsa, [uncompressed, :p256]}
            }

          _ ->
            raise EllipticCurveError, "p256"
        end

      @secp256k1_prefix ->
        case CryptoUtils.Curves.decompress_public_key_point(key_bytes, :secp256k1) do
          {:ok, uncompressed} ->
            %{
              curve: :secp256k1,
              jwt_alg: @secp256k1_jwt_alg,
              key_bytes: prefixed_bytes,
              algo_key: {:ecdsa, [uncompressed, :secp256k1]}
            }

          _ ->
            raise EllipticCurveError, "secp256k1"
        end

      _ ->
        raise UnsupportedPublicKeyCodecError, prefix
    end
  end

  def type_and_context_for_curve(:ed25519, purpose) do
    {type_for_curve(:ed25519, purpose), "https://w3id.org/security/suites/ed25519-2020/v1"}
  end

  def type_and_context_for_curve(:p256, purpose) do
    {type_for_curve(:p256, purpose), "https://w3id.org/security/suites/ecdsa-2019/v1"}
  end

  def type_and_context_for_curve(:secp256k1, purpose) do
    {type_for_curve(:secp256k1, purpose), "https://w3id.org/security/suites/secp256k1-2019/v1"}
  end

  def type_for_curve(:ed25519, _), do: "Multikey"
  def type_for_curve(:p256, :verification), do: "EcdsaSecp256r1VerificationKey2019"
  def type_for_curve(:secp256k1, :verification), do: "EcdsaSecp256k1VerificationKey2019"
  def type_for_curve(:p256, :encryption), do: "EcdsaSecp256r1EncryptionKey2019"
  def type_for_curve(:secp256k1, :encryption), do: "EcdsaSecp256k1EncryptionKey2019"

  # Operations

  @doc """
  Creates a did:plc operation.

  On success, returns a tuple `{:ok, {op, did}}`, where
  `op` is the data for a DID operation (type "plc_operation" or
  "plc_tombstone") and `did` is the DID key value.

  ## Examples

      iex> create_operation(%{field: value})
      {:ok, {%{"type" => "plc_operation"}, "did:plc:012345"}

      iex> create_operation(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_operation(params) do
    case CreateOperation.parse(params) do
      {:ok, {%CreateParams{did: did} = op, signer}} ->
        op = op |> normalize_op() |> add_signature(signer)

        did =
          if is_nil(did) do
            did_for_create_op(op)
          else
            IO.puts("applying did #{did}")
            did
          end

        {:ok, {op, did}}

      error ->
        error
    end
  end

  def update_operation(
        %{did: prev_did, cid: prev, operation: %{"type" => _type} = last_op},
        params
      )
      when is_binary(prev_did) and is_binary(prev) do
    with {:ok, %UpdateOperation{did: did, signer: signer} = update} <-
           UpdateOperation.parse(params) do
      # Omit sig so it doesn't accidentally make its way into the next operation
      {_old_sig, unsigned_op} =
        last_op
        |> normalize_op()
        |> Map.put("prev", prev)
        |> Map.pop("sig")

      update_op =
        unsigned_op
        |> apply_updates(update)
        |> add_signature(signer)

      {:ok, {update_op, did}}
    end
  end

  def apply_updates(normalized, update) do
    updates =
      if !is_nil(update.signingKey) do
        verification_methods =
          Map.get(normalized, "verificationMethods", %{})
          |> Map.merge(%{"atproto" => update.signingKey})

        %{"verificationMethods" => verification_methods}
      else
        %{}
      end

    updates =
      if !is_nil(update.handle) do
        formatted = CryptoUtils.ensure_atproto_prefix(update.handle)

        {also_known_as, inserted} =
          Map.get(normalized, "alsoKnownAs", [])
          |> Enum.reduce({[], false}, fn handle, {acc, found} ->
            if String.starts_with?(handle, "at://") do
              {[formatted | acc], true}
            else
              {[handle | acc], found}
            end
          end)

        also_known_as =
          if inserted do
            Enum.reverse(also_known_as)
          else
            [formatted | Enum.reverse(also_known_as)]
          end

        Map.put(updates, "alsoKnownAs", also_known_as)
      else
        updates
      end

    updates =
      if !is_nil(update.pds) do
        formatted = CryptoUtils.ensure_http_prefix(update.pds)

        services =
          Map.get(normalized, "services", %{})
          |> Map.merge(%{"type" => "AtprotoPersonalDataServer", "endpoint" => formatted})

        Map.put(updates, "services", services)
      else
        updates
      end

    updates =
      if !is_nil(update.rotationKeys) do
        Map.put(updates, "rotationKeys", update.rotationKeys)
      else
        updates
      end

    if map_size(updates) == 0 do
      normalized
    else
      Map.merge(normalized, updates)
    end
  end

  def normalize_op(%CreateParams{type: type, sig: sig} = op) when is_binary(type) do
    normalized_op = %{
      "type" => type,
      "verificationMethods" => op.verification_methods,
      "rotationKeys" => op.rotation_keys,
      "alsoKnownAs" => op.also_known_as,
      "services" => op.services,
      "prev" => op.prev
    }

    if is_nil(sig) do
      normalized_op
    else
      Map.put(normalized_op, "sig", sig)
    end
  end

  def normalize_op(%{"type" => _type} = op), do: op

  def assure_valid_next_op(did, ops, proposed)
      when is_binary(did) and is_list(ops) and is_map(proposed) do
    proposed =
      proposed
      |> normalize_op()
      |> assure_valid_op()

    if Enum.empty?(ops) do
      # special case if account creation
      {assure_valid_create_op(did, proposed), []}
    else
      assure_valid_op_order_and_sig(ops, proposed)
    end
  end

  def did_for_create_op(%{"prev" => nil} = op) do
    cbor = Map.delete(op, "sig") |> CBOR.encode()
    hash_of_genesis = :crypto.hash(:sha256, cbor)

    truncated_id =
      hash_of_genesis |> Base.encode32(case: :lower, padding: false) |> String.slice(0, 24)

    "did:plc:#{truncated_id}"
  end

  def did_for_create_op(_) do
    raise MisorderedOperationError, "not a genesis operation"
  end

  def cid_for_op(op) do
    op
    |> Cid.from_data()
    |> Cid.encode!(truncate: 24)
  end

  # Signatures

  def add_signature(%{"type" => type} = op, [_pub, algorithm, priv, curve] = _signer) do
    # {:ecdsa, [<<binary-size(32)>>, :secp256k1]}
    algorithm = String.to_existing_atom(algorithm)
    curve = String.to_existing_atom(curve)

    op =
      if type == "plc_tombstone" do
        Map.take(op, ["type", "prev"])
      else
        Map.delete(op, "sig")
      end

    cbor = CBOR.encode(op)
    signature = :crypto.sign(algorithm, :sha256, cbor, [priv, curve], [])
    Map.put(op, "sig", Base.encode64(signature))
  end

  def verify_signature(did_key, cbor, sig_bytes) do
    %{algo_key: algo_key} = parse_did_key!(did_key)
    # {:ecdsa, [<<binary-size(65)>>, :secp256k1]}
    {algorithm, [pub, curve]} = algo_key

    :crypto.verify(algorithm, :sha256, cbor, sig_bytes, [pub, curve], [])
  end

  # Private functions

  defp assure_valid_op_order_and_sig(ops, %{"prev" => prev} = proposed) do
    if is_nil(prev) do
      raise MisorderedOperationError, "no prev CID in operation"
    end

    index_of_prev = Enum.find_index(ops, fn %{cid: cid} -> prev == cid end)

    if is_nil(index_of_prev) do
      raise MisorderedOperationError, "prev CID #{prev} not found"
    end

    # if we are forking history, these are the ops still in the proposed
    # canonical history
    {ops_in_history, nullified} = Enum.split(ops, index_of_prev + 1)
    last_op = List.last(ops_in_history)

    if is_nil(last_op) do
      raise MisorderedOperationError, "no prev operation at #{index_of_prev}"
    end

    %{"type" => last_op_type, "rotationKeys" => rotation_keys} = Jason.decode!(last_op.operation)

    if last_op_type == "plc_tombstone" do
      raise MisorderedOperationError, "prev operation cannot be a tombstone"
    end

    case nullified do
      [] ->
        # does not involve nullification
        _did_key = assure_valid_sig(rotation_keys, proposed)
        {proposed, []}

      _ ->
        assure_valid_op_sig_when_nullified(rotation_keys, nullified, proposed)
    end
  end

  defp assure_valid_op_sig_when_nullified(
         rotation_keys,
         [%{operation: op_json, inserted_at: inserted_at} | _] = nullified,
         proposed
       ) do
    first_nullified = Jason.decode!(op_json)
    disputed_signer = assure_valid_sig(rotation_keys, first_nullified)
    more_powerful_keys = Enum.take_while(rotation_keys, fn key -> key != disputed_signer end)

    _did_key = assure_valid_sig(more_powerful_keys, proposed)

    # recovery key gets a 72hr window to do historical re-writes
    time_lapsed = DateTime.diff(DateTime.utc_now(), inserted_at, :second)

    if time_lapsed > 72 * 3600 do
      raise LateRecoveryError, time_lapsed
    end

    {proposed, Enum.map(nullified, fn %{cid: cid} -> cid end)}
  end

  defp assure_valid_create_op(_did, %{"type" => "plc_tombstone"}) do
    raise MisorderedOperationError, "genesis operation cannot be a tombstone"
  end

  defp assure_valid_create_op(did, %{"rotationKeys" => rotation_keys, "prev" => prev} = op) do
    if !is_nil(prev) do
      raise ImproperOperationError, op: op, message: "expected null prev on create"
    end

    assure_valid_op(op)
    assure_valid_sig(rotation_keys, op)
    expected_did = did_for_create_op(op)

    if did != expected_did do
      raise GenesisHashError, expected_did
    end

    op
  end

  defp assure_valid_op(%{"type" => "plc_tombstone"} = op), do: op

  defp assure_valid_op(%{"rotationKeys" => rotation_keys, "verificationMethods" => vms} = op) do
    # ensure we support the op's keys
    keys = Map.values(vms) ++ rotation_keys

    Enum.each(keys, fn key ->
      try do
        parse_did_key!(key)
      rescue
        _e ->
          raise UnsupportedKeyError, key
      end
    end)

    if Enum.count(rotation_keys) > 5 do
      raise ImproperOperationError, op: op, message: "too many rotation keys"
    end

    assure_rotation_keys(op, rotation_keys)
  end

  defp assure_valid_sig(allowed_did_keys, %{"sig" => sig} = op) when is_binary(sig) do
    _ = assure_rotation_keys(op, allowed_did_keys)

    with {:ok, sig_bytes} <- Base.decode64(sig),
         cbor <- Map.delete(op, "sig") |> normalize_op() |> CBOR.encode() do
      valid =
        Enum.find(allowed_did_keys, fn did_key ->
          verify_signature(did_key, cbor, sig_bytes)
        end)

      if is_nil(valid) do
        :error
      else
        valid
      end
    else
      _ -> raise InvalidSignatureError, op
    end
  end

  defp assure_valid_sig(_allowed_did_keys, op) do
    raise MissingSignatureError, op
  end

  defp assure_rotation_keys(op, []) do
    raise ImproperOperationError, op: op, message: "need at least one rotation key"
  end

  defp assure_rotation_keys(op, _), do: op
end
