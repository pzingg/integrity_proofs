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
      %__MODULE__{message: "point not on elliptic curve #{curve}"}
    end
  end

  defmodule GenesisHashError do
    defexception [:message]

    @impl true
    def exception(expected_did) do
      %__MODULE__{
        message: "expected did #{CryptoUtils.display_did(expected_did)} for genesis operation"
      }
    end
  end

  defmodule ImproperOperationError do
    defexception [:op, :message]

    @impl true
    def message(%{op: op, message: message}) do
      "#{message}, operation: #{CryptoUtils.display_op(op)}"
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
    defexception [:op, :allowed_keys]

    @impl true
    def message(%{op: op, allowed_keys: keys}) do
      "invalid signature, operation: #{CryptoUtils.display_op(op)}, keys #{CryptoUtils.display_did(keys)}"
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
    defexception [:op, :message]

    @impl true
    def message(%{op: op, message: message}) do
      "#{message}, operation: #{message}, #{CryptoUtils.display_op(op)}"
    end
  end

  defmodule MissingSignatureError do
    defexception [:message]

    @impl true
    def exception(op) do
      %__MODULE__{message: "missing signature, operation: #{CryptoUtils.display_op(op)}"}
    end
  end

  defmodule UnexpectedDidMethodError do
    defexception [:message]

    @impl true
    def exception(method) do
      %__MODULE__{message: "unexpected DID method #{method}"}
    end
  end

  defmodule UnsupportedKeyError do
    defexception [:message]

    @impl true
    def exception(key) do
      %__MODULE__{message: "unsupported key #{key}"}
    end
  end

  defmodule UnsupportedPublicKeyCodecError do
    defexception [:message]

    @impl true
    def exception(prefix) do
      %__MODULE__{message: "unsupported public key codec #{prefix}"}
    end
  end

  defmodule UnsupportedPublicKeyTypeError do
    defexception [:message]

    @impl true
    def exception(format) do
      %__MODULE__{message: "unsupported public key type #{format}"}
    end
  end

  @valid_did_methods [:web, :key, :plc, :example]
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
      parsed_did = parse_did!(identifier, options)

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
    method = String.to_atom(method)

    expected_did_methods = Keyword.get(options, :expected_did_methods, []) |> List.wrap()

    if expected_did_methods != [] && method not in expected_did_methods do
      raise UnexpectedDidMethodError, method
    end

    parsed = %{
      did_string: identifier,
      method: method,
      method_specific_id: method_specific_id
    }

    if Keyword.get(options, :method_only, false) do
      parsed
    else
      case method do
        :key ->
          validate_did!(:key, parsed, String.split(method_specific_id, ":"), options)

        :web ->
          validate_did!(:web, parsed, String.split(method_specific_id, ":"), options)

        :plc ->
          validate_did!(:plc, parsed, [method_specific_id], options)

        _ ->
          raise InvalidDidError, identifier
      end
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

  defp validate_did!(
         :plc,
         %{did_string: identifier, method_specific_id: base32_cid} = parsed,
         _,
         _options
       ) do
    if byte_size(base32_cid) != 24 || Regex.match?(~r/[^a-z2-7]/, base32_cid) do
      raise InvalidDidError, identifier
    end

    parsed
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
    parsed_did = parse_did!(identifier)

    %{
      context: sig_vm_context,
      verification_method: %{"id" => sig_vm_id} = signature_verification_method
    } = build_signature_method!(parsed_did, options)

    vms =
      if Keyword.get(options, :enable_encryption_key_derivation, false) do
        %{
          context: _context,
          verification_method: %{"id" => _enc_vm_id} = encryption_verification_method
        } = build_encryption_method!(parsed_did, options)

        [signature_verification_method, encryption_verification_method]
      else
        [signature_verification_method]
      end

    {vms, context} =
      case Keyword.get(options, :additional_vms) do
        more when is_map(more) and map_size(more) != 0 ->
          Enum.reduce(
            more,
            {vms, @base_context ++ [sig_vm_context]},
            fn
              {method_id,
               %{
                 type: type,
                 value: value
               } = vm_spec},
              {acc_vms, acc_context} ->
                value_key = Map.get(vm_spec, :value_type, "publicKeyMultibase")
                vm_context = Map.get(vm_spec, :context)

                vm = %{
                  "id" => "#" <> method_id,
                  "controller" => identifier,
                  "type" => type,
                  value_key => value
                }

                if is_nil(vm_context) do
                  {acc_vms ++ [vm], acc_context}
                else
                  {acc_vms ++ [vm], acc_context ++ List.wrap(vm_context)}
                end
            end
          )

        nil ->
          {vms, @base_context ++ [sig_vm_context]}
      end

    document = %{
      "@context" => context,
      "id" => identifier
    }

    document =
      case Keyword.get(options, :also_known_as) do
        nil -> document
        also_known_as -> Map.put(document, "alsoKnownAs", also_known_as)
      end

    document =
      Map.merge(document, %{
        "verificationMethod" => vms,
        "authentication" => [sig_vm_id],
        "assertionMethod" => [sig_vm_id],
        "capabilityInvocation" => [sig_vm_id],
        "capabilityDelegation" => [sig_vm_id]
      })

    case Keyword.get(options, :services) do
      services when is_map(services) and map_size(services) != 0 ->
        services =
          Enum.map(services, fn {service_id, %{type: type, endpoint: endpoint}} ->
            %{"id" => "#" <> service_id, "type" => type, "serviceEndpoint" => endpoint}
          end)

        Map.put(document, "service", services)

      _ ->
        document
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
  def valid_did_methods, do: @valid_did_methods

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
              "id" => "#" <> key_id,
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
        %{"id" => "#" <> service_id, "type" => type, "serviceEndpoint" => endpoint}
      end)

    # REVIEW Why are these keys singular? "verificationMethod", "service"
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
    %{multibase_value: multibase_value} = parse_did!(did, expected_did_methods: :key)

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
              algo_key: {:ecdsa, [uncompressed, :secp256r1]}
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

  def to_data(%{operation: op_json}) do
    %{"type" => type} = data = Jason.decode!(op_json)

    if type == "plc_tombstone" do
      nil
    else
      prev = Map.fetch!(data, "prev")

      keys_for_type(type)
      |> Enum.reduce(%{"type" => type, "prev" => prev}, fn field, acc ->
        case Map.get(data, field) do
          nil -> acc
          value -> Map.put(acc, field, value)
        end
      end)
    end
  end

  defp keys_for_type("create") do
    ["signingKey", "recoveryKey", "handle", "service", "sig"]
  end

  defp keys_for_type("plc_operation") do
    ["verificationMethods", "rotationKeys", "alsoKnownAs", "services", "sig"]
  end

  def to_plc_operation_data(%{operation: op_json} = op, decode_tombstone? \\ false) do
    case Jason.decode!(op_json) do
      %{"type" => "plc_tombstone"} = data ->
        if decode_tombstone? do
          data
        else
          nil
        end

      %{"type" => "plc_operation"} = data ->
        data

      %{"type" => "create", "prev" => nil} = data ->
        plc_operation_data = normalize_op(data, true)
        sig = Map.get(data, "sig")

        if is_nil(sig) do
          plc_operation_data
        else
          Map.put(plc_operation_data, "sig", sig)
        end

      _ ->
        raise ImproperOperationError, op: op, message: "invalid data #{op_json}"
    end
  end

  @doc """
  Builds an operation to create a new DID.

  `params` is a map with either all string keys or all atom keys
  used to build the operation. `params` values must include:

    * `:prev` - must be nil.
  ` * `:signer` - a keypair encoded as a flattened list.

  On success, returns a tuple `{:ok, {did, op, password}}`, where

    * `did` is the DID key value.
    * `op` is the data for a DID operation (type "plc_operation" or
      "plc_tombstone").
    * `password` is the cleartext password parsed from the params
      (which may be nil).

  ## Examples

      iex> create_operation(%{field: value})
      {:ok, {%{"type" => "plc_operation"}, "did:plc:012345", "cleartext_password"}}

      iex> create_operation(%{field: bad_value})
      {:error, %Ecto.Changeset{}}

  """
  def create_operation(params) do
    with {:ok, {%CreateParams{password: password} = op, signer}} <- CreateOperation.parse(params),
         op <- op |> normalize_op() |> add_signature(signer),
         {:ok, did} <- did_for_create_op(op) do
      # TODO keys_pem
      keys_pem = nil
      {:ok, {did, op, password, keys_pem}}
    end
  end

  @doc """
  Builds an operation that updates a DID.

    * `op` is the operation to be updated as returned from the
      did audit log.
    * `params` is a map with either all string keys or all atom keys
      used to build the new operation. `params` must include a
      `:signer` value (a keypair encoded as a flattened list).

    On success, returns a tuple `{:ok, {did, op}}`, where

    * `did` is the DID key value.
    * `op` is the data for the new DID operation (type "plc_operation" or
      "plc_tombstone").
  """
  def update_operation(%{did: op_did, cid: prev, operation: %{"type" => _type} = op}, params) do
    case UpdateOperation.parse(params) do
      {:ok, %UpdateOperation{did: did, signer: signer} = update} ->
        # Omit sig so it doesn't accidentally make its way into the next operation
        {_old_sig, unsigned_op} =
          op
          |> normalize_op(true)
          |> Map.put("prev", prev)
          |> Map.pop("sig")

        if did != op_did do
          raise ImproperOperationError,
            op: unsigned_op,
            message: "cannot apply update to a different did"
        end

        updated_op =
          unsigned_op
          |> apply_updates(update)
          |> add_signature(signer)

        {:ok, {did, updated_op}}

      error ->
        error
    end
  end

  def apply_updates(%{"prev" => prev}, %{type: "plc_tombstone"}) do
    %{"type" => "plc_tombstone", "prev" => prev}
  end

  def apply_updates(normalized, update) do
    updates =
      if !is_nil(update.signingKey) do
        # TODO validate signing key

        verification_methods =
          Map.get(normalized, "verificationMethods", %{})
          |> Map.merge(%{"atproto" => update.signingKey})

        %{"verificationMethods" => verification_methods}
      else
        %{}
      end

    updates =
      case update.alsoKnownAs do
        [_ | _] = aka ->
          atproto_handles = Enum.map(aka, &CryptoUtils.ensure_atproto_prefix/1)

          other_proto_handles =
            Map.get(normalized, "alsoKnownAs", [])
            |> Enum.filter(fn handle -> !CryptoUtils.atproto_uri?(handle) end)

          also_known_as = atproto_handles ++ other_proto_handles
          Map.put(updates, "alsoKnownAs", also_known_as)

        _ ->
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
        # TODO validate rotation keys

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

  def did_for_create_params(params) do
    case CreateOperation.parse(params, signer_optional: true) do
      {:ok, {%CreateParams{} = op, _signer}} ->
        op
        |> normalize_op()
        |> did_for_create_op()

      error ->
        error
    end
  end

  def did_for_create_op(%{"prev" => nil} = op) do
    {:ok, did_for_op(op)}
  end

  def did_for_create_op(_) do
    {:error, "not a create operation"}
  end

  def did_for_op(%{"type" => _type} = op) do
    cbor = Map.delete(op, "sig") |> CBOR.encode()
    hash_of_genesis = :crypto.hash(:sha256, cbor)

    truncated_id =
      hash_of_genesis |> Base.encode32(case: :lower, padding: false) |> String.slice(0, 24)

    "did:plc:#{truncated_id}"
  end

  # tombstones must have "prev"
  def normalize_op(params_or_op, force_v2 \\ false)

  def normalize_op(%CreateParams{type: "plc_tombstone", prev: nil} = op, _) do
    raise MisorderedOperationError, op: op, message: "genesis operation cannot be a tombstone"
  end

  def normalize_op(%CreateParams{type: "plc_tombstone", prev: prev, sig: sig}, _) do
    %{
      "type" => "plc_tombstone",
      "prev" => prev
    }
    |> maybe_add_sig(sig)
  end

  def normalize_op(%CreateParams{type: "create", prev: nil, sig: sig} = op, false) do
    handle = List.wrap(op.also_known_as) |> hd()
    signing_key = Map.get(op.verification_methods, "atproto")
    recovery_key = List.wrap(op.rotation_keys) |> hd()
    service = get_in(op.services, ["atproto_pds", "endpoint"])

    if is_nil(handle) || is_nil(signing_key) || is_nil(recovery_key) || is_nil(service) do
      raise ImproperOperationError, op: op, message: "missing elements"
    end

    %{
      "type" => "create",
      "handle" => handle,
      "signingKey" => signing_key,
      "recoveryKey" => recovery_key,
      "service" => service,
      "prev" => nil
    }
    |> maybe_add_sig(sig)
  end

  def normalize_op(%CreateParams{type: "create"} = op, _) do
    raise ImproperOperationError, op: op, message: "prev must be null"
  end

  def normalize_op(%CreateParams{type: type, sig: sig} = op, _) when is_binary(type) do
    %{
      "type" => type,
      "verificationMethods" => op.verification_methods,
      "rotationKeys" => op.rotation_keys,
      "alsoKnownAs" => op.also_known_as,
      "services" => op.services,
      "prev" => op.prev
    }
    |> maybe_add_sig(sig)
  end

  def normalize_op(%{"type" => "create"} = data, true) do
    %{
      "type" => "plc_operation",
      "verificationMethods" => %{"atproto" => Map.fetch!(data, "signingKey")},
      "rotationKeys" => [Map.fetch!(data, "recoveryKey")],
      "alsoKnownAs" => [Map.fetch!(data, "handle")],
      "services" => %{
        "atproto_pds" => %{
          "type" => "AtprotoPersonalDataServer",
          "endpoint" => Map.fetch!(data, "service")
        }
      },
      "prev" => nil
    }
  end

  def normalize_op(%{"type" => _type} = op, _), do: op

  def maybe_add_sig(op, nil), do: op
  def maybe_add_sig(op, sig), do: Map.put(op, "sig", sig)

  def assure_valid_next_op(did, ops, proposed)
      when is_binary(did) and is_list(ops) and is_map(proposed) do
    proposed =
      proposed
      |> normalize_op()
      |> assure_valid_op()

    if Enum.empty?(ops) do
      # special case if account creation
      {assure_valid_creation_op(did, proposed), []}
    else
      assure_valid_op_order_and_sig(ops, proposed)
    end
  end

  def cid_for_op(op) do
    {cbor, _unsigned_op} = cbor_encode(op)

    cbor
    |> Cid.from_cbor()
    |> Cid.encode!(truncate: 24)
  end

  def validate_operation_log!(did, [%{"type" => first_type} = first | rest]) do
    if first_type not in ["create", "plc_operation"] do
      raise ImproperOperationError, op: first, message: "incorrect structure"
    end

    # ensure the first op is a valid & signed create operation
    first_op = assure_valid_creation_op(did, first)
    prev = cid_for_op(first)

    {%{"type" => type} = final_op, _, _} =
      Enum.reduce(rest, {first_op, prev, false}, fn %{"type" => type, "prev" => op_prev} = op,
                                                    {key_op, prev, saw_tombstone} ->
        # if tombstone found before last op, throw
        if saw_tombstone do
          raise MisorderedOperationError, op: op, message: "tombstone not last in log of #{did}"
        end

        if is_nil(op_prev) || op_prev != prev do
          raise MisorderedOperationError,
            op: op,
            message: "prev CID #{op_prev} does not match #{prev} in log of #{did}"
        end

        rotation_keys =
          case key_op do
            %{"rotationKeys" => keys} -> keys
            %{"recoveryKey" => key} -> [key]
            _ -> []
          end

        assure_valid_sig(rotation_keys, op)
        prev = cid_for_op(op)
        {op, prev, type == "plc_tombstone"}
      end)

    # if tombstone is last op, return nil
    if type == "plc_tombstone" do
      nil
    else
      final_op
    end
  end

  def validate_operation_log!(_did, []) do
    raise ImproperOperationError, op: nil, message: "incorrect structure"
  end

  # Signatures

  def cbor_encode(%{"type" => "plc_tombstone"} = op) do
    unsigned_op = Map.take(op, ["type", "prev"])
    {CBOR.encode(unsigned_op), unsigned_op}
  end

  def cbor_encode(op) do
    unsigned_op = Map.delete(op, "sig")
    {CBOR.encode(unsigned_op), unsigned_op}
  end

  def add_signature(op, [_did, algorithm, priv, curve] = _signer) do
    # ["did:key:...", "ecdsa", <<binary-size(32)>>, "secp256k1"] = signer

    algorithm = String.to_existing_atom(algorithm)
    curve = String.to_existing_atom(curve)

    {cbor, _unsigned_op} = cbor_encode(op)
    sig_bytes = :crypto.sign(algorithm, :sha256, cbor, [priv, curve], [])
    Map.put(op, "sig", Base.encode64(sig_bytes))
  end

  def verify_signature(did, cbor, sig_bytes) do
    %{algo_key: algo_key} = parse_did_key!(did)
    # {:ecdsa, [<<binary-size(65)>>, :secp256k1]} = algo_key

    {algorithm, [pub, curve]} = algo_key
    :crypto.verify(algorithm, :sha256, cbor, sig_bytes, [pub, curve], [])
  end

  # Private functions

  defp assure_valid_op_order_and_sig(_ops, %{"type" => "create"} = proposed) do
    raise ImproperOperationError,
      op: proposed,
      message: "create type not allowed for an existing did"
  end

  defp assure_valid_op_order_and_sig(ops, %{"prev" => prev} = proposed) do
    if is_nil(prev) do
      raise MisorderedOperationError,
        op: proposed,
        message: "create operation not allowed for an existing did"
    end

    index_of_prev = Enum.find_index(ops, fn %{cid: cid} -> prev == cid end)

    if is_nil(index_of_prev) do
      raise MisorderedOperationError, op: proposed, message: "prev CID #{prev} not found"
    end

    # if we are forking history, these are the ops still in the proposed
    # canonical history
    {ops_in_history, nullified} = Enum.split(ops, index_of_prev + 1)
    last_op = List.last(ops_in_history)

    if is_nil(last_op) do
      raise MisorderedOperationError,
        op: proposed,
        message: "no prev operation at #{index_of_prev}"
    end

    rotation_keys =
      case to_plc_operation_data(last_op, true) do
        %{"type" => "plc_tombstone"} ->
          raise MisorderedOperationError,
            op: proposed,
            message: "prev operation cannot be a tombstone"

        %{"rotationKeys" => keys} ->
          keys

        _ ->
          []
      end

    case nullified do
      [] ->
        # does not involve nullification
        _did_key = assure_valid_sig(rotation_keys, proposed)
        {proposed, []}

      _ ->
        _ = assure_valid_op_sig_when_nullified(rotation_keys, nullified, proposed)

        nullified_cids = Enum.map(nullified, fn %{cid: cid} -> cid end)
        {proposed, nullified_cids}
    end
  end

  defp assure_valid_op_sig_when_nullified(
         rotation_keys,
         [%{operation: op_json, inserted_at: inserted_at} | _] = _nullified,
         proposed
       ) do
    first_nullified = Jason.decode!(op_json)
    disputed_signer = assure_valid_sig(rotation_keys, first_nullified)
    more_powerful_keys = Enum.take_while(rotation_keys, fn key -> key != disputed_signer end)
    _did_key = assure_valid_sig(more_powerful_keys, proposed)

    # recovery key gets a 72hr window to do historical re-writes
    time_lapsed = NaiveDateTime.diff(NaiveDateTime.utc_now(), inserted_at, :second)

    if time_lapsed > 72 * 3600 do
      raise LateRecoveryError, time_lapsed
    end

    proposed
  end

  # tombstones must have "prev"
  defp assure_valid_creation_op(_did, %{"type" => "plc_tombstone"} = op) do
    raise MisorderedOperationError, op: op, message: "genesis operation cannot be a tombstone"
  end

  defp assure_valid_creation_op(
         did,
         %{"type" => "create", "recoveryKey" => recovery_key, "prev" => prev} = op
       ) do
    validate_creation_op(did, op, prev, [recovery_key])
  end

  defp assure_valid_creation_op(did, %{"rotationKeys" => rotation_keys, "prev" => prev} = op) do
    validate_creation_op(did, op, prev, rotation_keys)
  end

  defp validate_creation_op(did, op, prev, rotation_keys) do
    assure_valid_op(op)
    assure_valid_sig(rotation_keys, op)

    expected_did = did_for_op(op)

    if expected_did != did do
      raise GenesisHashError, expected_did
    end

    if !is_nil(prev) do
      raise ImproperOperationError, op: op, message: "expected null prev on create"
    end

    op
  end

  defp assure_valid_op(%{"type" => "plc_tombstone"} = op), do: op

  defp assure_valid_op(
         %{"type" => "create", "signingKey" => signing_key, "recoveryKey" => recovery_key} = op
       ) do
    validate_keys(op, [signing_key], [recovery_key])
  end

  defp assure_valid_op(%{"rotationKeys" => rotation_keys, "verificationMethods" => vms} = op) do
    signing_keys = Map.values(vms)
    validate_keys(op, signing_keys, rotation_keys)
  end

  # ensure we support the op's keys
  defp validate_keys(op, signing_keys, rotation_keys) do
    keys = signing_keys ++ rotation_keys

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
    try do
      _ = assure_rotation_keys(op, allowed_did_keys)
    rescue
      _ -> raise InvalidSignatureError, op: op, allowed_keys: allowed_did_keys
    end

    {cbor, _unsigned_op} = cbor_encode(op)

    with {:ok, sig_bytes} <- Base.decode64(sig),
         {:found, valid} when is_binary(valid) <-
           {:found, Enum.find(allowed_did_keys, &verify_signature(&1, cbor, sig_bytes))} do
      valid
    else
      _ ->
        raise InvalidSignatureError, op: op, allowed_keys: allowed_did_keys
    end
  end

  # no signature element
  defp assure_valid_sig(_allowed_did_keys, op), do: raise(MissingSignatureError, op)

  defp assure_rotation_keys(op, []) do
    raise ImproperOperationError, op: op, message: "need at least one rotation key"
  end

  defp assure_rotation_keys(op, _), do: op
end
