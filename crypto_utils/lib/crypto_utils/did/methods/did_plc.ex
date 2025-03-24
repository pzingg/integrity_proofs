defmodule CryptoUtils.Did.Methods.DidPlc do
  @moduledoc """
  Handler for the did:key method.
  """

  @behaviour CryptoUtils.Did.Method
  @behaviour CryptoUtils.Did.Resolver

  alias CryptoUtils.{Cid, Did}
  alias CryptoUtils.Did.{DocumentMetadata, ResolutionMetadata}
  alias CryptoUtils.Did.Methods.DidPlc.{CreateOperation, CreateParams, UpdateOperation}

  defmodule GenesisHashError do
    defexception [:message]

    @impl true
    def exception(expected_did) do
      %__MODULE__{
        message: "expected DID #{CryptoUtils.display_did(expected_did)} for genesis operation"
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

  @impl CryptoUtils.Did.Method
  def name() do
    "plc"
  end

  @impl CryptoUtils.Did.Method
  def to_resolver() do
    __MODULE__
  end

  @impl CryptoUtils.Did.Method
  def validate(%{method_specific_id: base32_cid} = parsed, _) do
    if byte_size(base32_cid) == 24 && Regex.match?(~r/^[a-z2-7]+$/, base32_cid) do
      {:ok, parsed}
    else
      :error
    end
  end

  @impl CryptoUtils.Did.Resolver
  def resolve(did, opts) do
    with {:ok, {res_meta, doc_data, doc_meta}} <- resolve_representation(did, opts),
         {:ok, doc} <- Jason.decode(doc_data) do
      # https://www.w3.org/TR/did-core/#did-resolution-metadata
      # contentType - "MUST NOT be present if the resolve function was called"
      {:ok, {%ResolutionMetadata{res_meta | content_type: nil}, doc, doc_meta}}
    else
      {:error, reason} ->
        error_result(reason)
    end
  end

  @impl CryptoUtils.Did.Resolver
  def resolve_representation(did, opts) do
    case did_plc_uri(did, opts) do
      {:ok, uri} ->
        url = URI.to_string(uri)
        env_options = Elixir.Application.get_env(:crypto_utils, :did_plc_req_options, [])
        opts = Keyword.merge(env_options, opts)
        # TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security
        {accept, opts} = Keyword.pop(opts, :accept, "application/json")
        opts = Keyword.put(opts, :headers, %{"accept" => accept})

        case CryptoUtils.HttpClient.fetch(url, opts) do
          {:ok, body} ->
            # TODO: set document created/updated metadata from HTTP headers?
            res_meta = %ResolutionMetadata{content_type: "application/did+ld+json"}
            doc_meta = %DocumentMetadata{}

            {:ok, {res_meta, body, doc_meta}}

          {:error, _, status_code} ->
            {:error, "did:plc HTTP request to #{url} failed: #{status_code}"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Resolve the URL for a did:plc identifier.
  """
  def did_plc_uri(did, opts \\ [])

  def did_plc_uri(did, opts) when is_binary(did) do
    try do
      opts = Keyword.put(opts, :expected_did_methods, [:plc])
      parsed_did = Did.parse_did!(did, opts)
      did_plc_uri(parsed_did, opts)
    rescue
      _ -> {:error, "invalid did:plc #{did}"}
    end
  end

  def did_plc_uri(%{did_string: identifier}, opts) do
    uri = Keyword.get(opts, :plc_server_url, "https://plc.directory") |> URI.parse()
    {:ok, %URI{uri | path: "/#{identifier}"}}
  end

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
            message: "cannot apply update to a different DID"
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
    Map.put(op, "sig", Base.url_encode64(sig_bytes, padding: false))
  end

  def verify_signature(did, cbor, sig_bytes) do
    %{algo_key: algo_key} = CryptoUtils.Did.parse_did!(did, expected_did_methods: [:key])
    # {:ecdsa, [<<binary-size(65)>>, :secp256k1]} = algo_key

    {algorithm, [pub, curve]} = algo_key
    :crypto.verify(algorithm, :sha256, cbor, sig_bytes, [pub, curve], [])
  end

  # Private functions

  defp assure_valid_op_order_and_sig(_ops, %{"type" => "create"} = proposed) do
    raise ImproperOperationError,
      op: proposed,
      message: "create type not allowed for an existing DID"
  end

  defp assure_valid_op_order_and_sig(ops, %{"prev" => prev} = proposed) do
    if is_nil(prev) do
      raise MisorderedOperationError,
        op: proposed,
        message: "create operation not allowed for an existing DID"
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

    Enum.each(keys, fn did ->
      try do
        CryptoUtils.Did.parse_did!(did, expected_did_methods: [:key])
      rescue
        _e ->
          raise CryptoUtils.Did.UnsupportedKeyError, did
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

    with {:ok, sig_bytes} <- Base.url_decode64(sig, padding: false),
         {:found, valid} when is_binary(valid) <-
           {:found, Enum.find(allowed_did_keys, &verify_signature(&1, cbor, sig_bytes))} do
      valid
    else
      _ ->
        raise InvalidSignatureError, op: op, allowed_keys: allowed_did_keys
    end
  end

  # no signature element
  defp assure_valid_sig(_allowed_did_keys, op) do
    raise MissingSignatureError, op
  end

  defp assure_rotation_keys(op, []) do
    raise ImproperOperationError, op: op, message: "need at least one rotation key"
  end

  defp assure_rotation_keys(op, _), do: op

  defp error_result(error) do
    {:error, {%ResolutionMetadata{error: error}, nil, nil}}
  end
end
