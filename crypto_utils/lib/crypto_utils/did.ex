defmodule CryptoUtils.Did do
  @moduledoc """
  Basic DID handling.
  """

  alias CryptoUtils.Keys.KeyFormat

  defmodule InvalidDidError do
    defexception [:message]

    @impl true
    def exception(did) do
      %__MODULE__{message: "Invalid DID #{did}"}
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

  @type resolution_input_option() ::
          {:client, module()}
          | {:user_agent, String.t()}
          | {:accept, String.t()}
          | {:version_id, String.t()}
          | {:version_time, String.t()}
          | {:no_cache, bool()}
          | {:property_set, map()}

  @typedoc """
  [DID Resolution Options](https://www.w3.org/TR/did-core/#did-resolution-options).

  Used as input to `DIDResolver::resolve/2`.
  """
  @type resolution_input_metadata() :: [resolution_input_option()]

  @type dereferencing_input_option() ::
          {:accept, String.t()}
          | {:service_type, String.t()}
          | {:follow_redirect, bool()}
          | {:property_set, map()}

  @typedoc """
  [DID URL Dereferencing Options](https://www.w3.org/TR/did-core/#did-url-dereferencing-options)

  Used as input to [DID URL dereferencing][dereference].
  """
  @type dereferencing_input_metadata() :: [dereferencing_input_option()]

  defmodule ResolutionMetadata do
    @moduledoc """
    [DID Resolution Metadata](https://www.w3.org/TR/did-core/#did-resolution-metadata)

    Specified in [DID Resolution](https://w3c-ccg.github.io/did-resolution/#output-resolutionmetadata)
    """

    defstruct [
      :error,
      :content_type,
      property_set: %{}
    ]

    @type t() :: %__MODULE__{
            error: String.t() | nil,
            content_type: String.t() | nil,
            property_set: map()
          }
  end

  defmodule DocumentMetadata do
    @moduledoc """
    Metadata structure describing a DID document in a DID Resolution Result.

    Specified:
    - in [DID Core](https://www.w3.org/TR/did-core/#dfn-diddocumentmetadata)
    - in [DID Resolution](https://w3c-ccg.github.io/did-resolution/#output-documentmetadata)
    - in [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/#did-document-metadata)

    Also returned from
    [DID URL dereferencing](https://www.w3.org/TR/did-core/#did-url-dereferencing) ([`dereference`]).
    """

    defstruct [
      :created,
      :updated,
      :deactivated,
      property_set: %{}
    ]

    @type t() :: %__MODULE__{
            created: NaiveDateTime.t() | nil,
            updated: NaiveDateTime.t() | nil,
            deactivated: boolean() | nil,
            property_set: map()
          }
  end

  @typedoc """
  Type of content returned by dereference.
  """
  @type content() ::
          {:did_document, binary()}
          | {:url, binary()}
          | {:object, map()}
          | {:data, binary()}
          | nil

  defmodule DereferencingMetadata do
    @moduledoc """
    [DID URL dereferencing metadata](https://www.w3.org/TR/did-core/#did-url-dereferencing-metadata).

    Returned from [DID URL dereferencing][dereference].
    """
    defstruct [
      :error,
      :content_type,
      property_set: %{}
    ]

    @type t() :: %__MODULE__{
            error: String.t() | nil,
            content_type: String.t() | nil,
            property_set: map()
          }
  end

  @type basic_parts() :: %{
          did_string: String.t(),
          method: String.t(),
          method_specific_id: String.t()
        }

  @valid_did_methods [:web, :key, :plc, :example]
  @known_signature_key_formats [
    "Multikey",
    "JsonWebKey2020",
    "Ed25519VerificationKey2018",
    "Ed25519VerificationKey2020",
    "EcdsaSecp256r1VerificationKey2019",
    "EcdsaSecp256k1VerificationKey2019"
  ]
  @known_encryption_key_formats [
    "Multikey",
    "JsonWebKey2020",
    "X25519KeyAgreementKey2020",
    "EcdsaSecp256r1AgreementKey2019",
    "EcdsaSecp256k1AgreementKey2019"
  ]

  @base_context [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/data-integrity/v1",
    "https://w3id.org/security/jwk/v1",
    "https://w3id.org/security/multikey/v1"
  ]

  # DIDs

  @doc """
  Lookup parts and resolver method for a DID.
  """
  def parse_basic!(identifier, options \\ []) do
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

    method_module = CryptoUtils.Did.Method.lookup!(method)
    resolver = method_module.to_resolver()

    %{
      did_string: identifier,
      method: method,
      method_specific_id: method_specific_id,
      method_module: method_module,
      resolver: resolver
    }
  end

  def get_method!(identifier) do
    %{method_module: method_module} = parse_basic!(identifier)
    method_module
  end

  @doc """
  Parse a DID, optionally validating via the resolver.

  Returns a map with items
    * `:version`
    * `:multibase_value`
    * `:curve`
    * `:key_bytes`
    * `:algo_key`
    * `:jwk`
    * `:jwt_alg`
    * `:contexts`
  """
  def parse_did!(identifier, options \\ []) do
    %{resolver: resolver} = parsed = parse_basic!(identifier, options)

    if Keyword.get(options, :method_only, false) do
      parsed
    else
      case resolver.validate(parsed, options) do
        {:ok, parsed} ->
          parsed

        _ ->
          raise InvalidDidError, identifier
      end
    end
  end

  @doc """
  Resolve a DID, optionally validating via the resolver.
  """
  def resolve_did!(identifier, options \\ []) do
    %{resolver: resolver} = parsed = parse_basic!(identifier, options)

    case resolver.validate(parsed, options) do
      {:ok, parsed} ->
        resolver.resolve(parsed, options)

      _ ->
        raise InvalidDidError, identifier
    end
  end

  ## Creating DID documents

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
  def format_did_document!(identifier, options \\ []) do
    parsed_did = parse_did!(identifier)

    %{
      verification_method: %{"id" => sig_vm_id} = signature_verification_method
    } = sig_method = build_signature_method!(parsed_did, options)

    sig_context = Map.get(sig_method, :context)

    relationships = %{
      "assertionMethod" => [sig_vm_id],
      "authentication" => [sig_vm_id],
      "capabilityInvocation" => [sig_vm_id],
      "capabilityDelegation" => [sig_vm_id]
    }

    {vms, relationships, enc_context} =
      if Keyword.get(options, :enable_encryption_key_derivation, false) do
        %{
          verification_method: %{"id" => enc_vm_id} = encryption_verification_method
        } = enc_method = build_encryption_method!(parsed_did, options)

        enc_context = Map.get(enc_method, :context)

        {[signature_verification_method, encryption_verification_method],
         Map.put(relationships, "keyAgreement", enc_vm_id), enc_context}
      else
        {[signature_verification_method], relationships, nil}
      end

    acc_context =
      (@base_context ++ [sig_context, enc_context])
      |> Enum.filter(fn ctx -> !is_nil(ctx) end)

    acc = {vms, relationships, acc_context}

    {vms, relationships, context} =
      case Keyword.get(options, :additional_vms) do
        more when is_map(more) and map_size(more) != 0 ->
          Enum.reduce(
            more,
            acc,
            fn
              {method_id,
               %{
                 type: type,
                 value: value
               } = vm_spec},
              {acc_vms, acc_rel, acc_context} ->
                value_key = Map.get(vm_spec, :value_type, "publicKeyMultibase")
                vm_context = Map.get(vm_spec, :context)
                relationships = Map.get(vm_spec, :relationships, [])
                vm_id = "#" <> method_id

                vm = %{
                  "id" => vm_id,
                  "controller" => identifier,
                  "type" => type,
                  value_key => value
                }

                acc_rel =
                  case relationships do
                    [] ->
                      acc_rel

                    rels when is_list(rels) ->
                      Enum.reduce(rels, acc_rel, fn rel ->
                        Map.update(acc_rel, rel, [], fn vm_ids ->
                          case vm_ids do
                            [] -> vm_id
                            non_empty -> [vm_id | List.wrap(non_empty)]
                          end
                        end)
                      end)
                  end

                acc_context =
                  if is_nil(vm_context) do
                    acc_context
                  else
                    acc_context ++ List.wrap(vm_context)
                  end

                {acc_vms ++ [vm], acc_rel, acc_context}
            end
          )

        _ ->
          acc
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
      document
      |> Map.put("verificationMethod", vms)
      |> Map.merge(relationships)

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

  ## Querying DID documents

  def get_service_endpoint(%{"service" => svcs}, service_type) do
    Enum.find(svcs, fn %{"type" => type} -> type == service_type end)
    |> case do
      %{"serviceEndpoint" => endpoint} -> {:ok, endpoint}
      _ -> {:error, "service type #{service_type} not found in DID document"}
    end
  end

  def get_public_key(did_document, fmt, relationship \\ "assertionMethod")

  def get_public_key(
        %{"verificationMethod" => [%{"id" => first_vm_id} | _] = vm} = doc,
        fmt,
        relationship
      ) do
    vm_id =
      case Map.get(doc, relationship) do
        [id | _] -> "#" <> id
        _ -> first_vm_id
      end

    Enum.find(vm, fn %{"id" => id} -> String.ends_with?(id, vm_id) end)
    |> case do
      %{"publicKeyMultibase" => _value} = vm ->
        CryptoUtils.Keys.extract_multikey(vm, fmt)

      _ ->
        {:error, "multibase method #{vm_id} not found in DID document"}
    end
  end

  def get_public_key(_doc, _fmt, _relationship), do: {:error, "not a valid DID document"}

  ## DID document support

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
        %{
          did_string: identifier
          # method: method,
          # multibase_value: multibase_value,
          # contexts: %{signature: {type, type_iri}}
        } = parsed_did,
        options
      ) do
    {public_key_format, context} = parse_key_format_and_context(:signature, parsed_did, options)

    multibase_value =
      Map.get(parsed_did, :multibase_value) || Keyword.get(options, :multibase_value)

    if is_nil(multibase_value) do
      raise InvalidDidError, identifier
    end

    # Not in standard
    fragment = Keyword.get(options, :signature_method_fragment, multibase_value)

    vm = %{
      verification_method: %{
        "id" => identifier <> "#" <> fragment,
        "type" => public_key_format,
        "controller" => identifier,
        "publicKeyMultibase" => multibase_value
      }
    }

    if is_nil(context) do
      vm
    else
      Map.put(vm, :context, %{public_key_format => context})
    end
  end

  def parse_key_format_and_context(context, parsed_did, options) do
    public_key_format = Keyword.get(options, :public_key_format)

    if !is_nil(public_key_format) && KeyFormat.base_format?(public_key_format) do
      {public_key_format, nil}
    else
      case get_in(parsed_did, [:contexts, context]) do
        {type, type_iri} ->
          {type, type_iri}

        _ ->
          {"Multikey", nil}
      end
    end
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
        %{
          did_string: identifier
          # method: method,
          # multibase_value: multibase_value
        } = parsed_did,
        options
      ) do
    {public_key_format, context} = parse_key_format_and_context(:encryption, parsed_did, options)

    multibase_value =
      Map.get(parsed_did, :multibase_value) || Keyword.get(options, :multibase_value)

    if is_nil(multibase_value) do
      raise InvalidDidError, identifier
    end

    # Not in standard
    fragment = Keyword.get(options, :encryption_method_fragment, multibase_value)

    vm = %{
      verification_method: %{
        "id" => identifier <> "#" <> fragment,
        "type" => public_key_format,
        "controller" => identifier,
        "publicKeyMultibase" => multibase_value
      }
    }

    if is_nil(context) do
      vm
    else
      Map.put(vm, :context, %{public_key_format => context})
    end
  end

  @doc """
  Select an object in the DID document.
  `resource_id` should include the full DID id, "#" and fragment.

  Used in [DID URL dereferencing - Dereferencing the Secondary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary), Step 1.1 "... select the JSON-LD object whose id property matches the input DID URL ..."
  """
  def select_object(%{"id" => doc_id} = doc, resource_id) do
    relative_id = String.replace_leading(resource_id, doc_id, "")

    [
      "verificationMethod",
      "authentication",
      "assertionMethod",
      "keyAgreement",
      "capabilityInvocation",
      "capabilityDelegation",
      "publicKey"
    ]
    |> Enum.map(fn key ->
      case Map.get(doc, key) do
        nil -> nil
        object -> List.wrap(object)
      end
    end)
    |> List.flatten()
    |> Enum.filter(fn obj -> !is_nil(obj) end)
    |> Enum.find(fn
      %{"id" => object_id} ->
        object_id in [resource_id, relative_id]

      _ ->
        false
    end)
  end

  @doc """
  Select a service endpoint object in the DID document.
  `fragment` does not start with a "#".

  Used in [DID URL Dereferencing - Dereferencing the Primary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary), Step
  1.1 "... select the service endpoint whose id property contains a fragment which matches
  the value of the service DID parameter of the input DID URL"
  """
  def select_service(%{"service" => services}, fragment) do
    services
    |> List.wrap()
    |> Enum.find(fn
      %{"id" => service_id} ->
        case String.split(service_id, "#", parts: 2) do
          [_, service_fragment] ->
            service_fragment == fragment

          _ ->
            false
        end

      _ ->
        false
    end)
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
end
