defmodule CryptoUtils.Plc.CreateOperation do
  @moduledoc """
  Parsing and validating inputs for creating a did:plc operation.

  Inputs could be for Bluesky v1 "create" , "plc_operation", or "plc_tombstone".
  """

  use Ecto.Schema
  import Ecto.Changeset

  alias CryptoUtils.Plc.CreateParams

  embedded_schema do
    field(:did, :string)
    field(:type, :string)
    field(:prev, :string)
    field(:signer, {:array, :string})
    field(:sig, :string)
    field(:signingKey, :string)
    field(:recoveryKey, :string)
    field(:handle, :string)
    field(:service, :string)
    field(:verificationMethods, :map)
    field(:rotationKeys, {:array, :string})
    field(:alsoKnownAs, {:array, :string})
    field(:services, :map)
    field(:password, :string)
  end

  def parse(params, opts \\ [])

  def parse(params, opts) when is_list(params), do: Map.new(params) |> parse(opts)

  def parse(params, opts) when is_map(params) do
    case changeset(%__MODULE__{}, params, opts) |> apply_action(:create) do
      {:ok, %{type: type} = op} ->
        case type do
          "plc_tombstone" ->
            {:ok,
             {%CreateParams{did: op.did, type: "plc_tombstone", prev: op.prev, sig: op.sig},
              op.signer}}

          _ ->
            type =
              if type not in ["create", "plc_operation"] do
                "plc_operation"
              else
                type
              end

            verification_methods =
              case op.verificationMethods do
                vms when is_map(vms) and map_size(vms) != 0 -> vms
                _ -> %{"atproto" => op.signingKey}
              end

            signing_key = Map.get(verification_methods, "atproto")

            rotation_keys =
              cond do
                is_map(op.rotationKeys) && map_size(op.rotationKeys) != 0 ->
                  op.rotationKeys

                !is_nil(op.recoveryKey) && !is_nil(signing_key) ->
                  [op.recoveryKey, signing_key]

                !is_nil(op.recoveryKey) ->
                  [op.recoveryKey]

                true ->
                  []
              end

            also_known_as =
              case op.alsoKnownAs do
                [_ | _] = aka -> Enum.map(aka, &CryptoUtils.ensure_atproto_prefix/1)
                _ -> [CryptoUtils.ensure_atproto_prefix(op.handle)]
              end

            services =
              case op.services do
                svcs when is_map(svcs) and map_size(svcs) != 0 ->
                  svcs

                _ ->
                  %{
                    "atproto_pds" => %{
                      "type" => "AtprotoPersonalDataServer",
                      "endpoint" => CryptoUtils.ensure_http_prefix(op.service)
                    }
                  }
              end

            {:ok,
             {%CreateParams{
                did: op.did,
                type: type,
                prev: op.prev,
                sig: op.sig,
                verification_methods: verification_methods,
                rotation_keys: rotation_keys,
                also_known_as: also_known_as,
                services: services,
                password: op.password
              }, op.signer}}
        end

      error ->
        error
    end
  end

  def changeset(op, attrs \\ %{}, opts \\ []) do
    changeset =
      op
      |> cast(attrs, [
        :did,
        :type,
        :prev,
        :signer,
        :sig,
        :signingKey,
        :recoveryKey,
        :handle,
        :service,
        :rotationKeys,
        :alsoKnownAs,
        :verificationMethods,
        :services,
        :password
      ])

    changeset =
      if Keyword.get(opts, :signer_optional, false) do
        changeset
      else
        validate_required(changeset, :signer)
      end

    changeset
    |> validate_type()
    |> validate_op()
  end

  defp validate_type(changeset) do
    prev = get_change(changeset, :prev)

    if is_nil(prev) do
      validate_inclusion(changeset, :type, ["create", "plc_operation"],
        message: "must be create or plc_operation for did creation"
      )
    else
      validate_inclusion(changeset, :type, ["plc_operation", "plc_tombstone"],
        message: "must be plc_operation or plc_tombstone for did updates"
      )
    end
  end

  defp validate_op(changeset) do
    case get_change(changeset, :type) do
      "plc_tombstone" ->
        validate_required(changeset, [:prev])

      "plc_operation" ->
        changeset
        |> validate_verification_methods()
        |> validate_rotation_keys()
        |> validate_also_known_as()
        |> validate_services()

      "create" ->
        changeset
        |> validate_required([:signingKey])
        |> validate_verification_methods()
        |> validate_rotation_keys()
        |> validate_also_known_as()
        |> validate_services()

      _ ->
        changeset
    end
  end

  def validate_rotation_keys(changeset) do
    case get_change(changeset, :rotationKeys) do
      [_ | _] ->
        changeset

      _ ->
        case get_change(changeset, :recoveryKey) do
          key when is_binary(key) -> changeset
          _ -> add_error(changeset, :recoveryKey, "can't be blank")
        end
    end
  end

  def validate_also_known_as(changeset) do
    case get_change(changeset, :alsoKnownAs) do
      [_ | _] ->
        changeset

      _ ->
        case get_change(changeset, :handle) do
          key when is_binary(key) -> changeset
          _ -> add_error(changeset, :handle, "can't be blank")
        end
    end
  end

  def validate_verification_methods(changeset) do
    case get_change(changeset, :verificationMethods) do
      vms when is_map(vms) and map_size(vms) != 0 ->
        changeset

      _ ->
        case get_change(changeset, :signingKey) do
          key when is_binary(key) -> changeset
          _ -> add_error(changeset, :signingKey, "can't be blank")
        end
    end
  end

  def validate_services(changeset) do
    case get_change(changeset, :services) do
      svcs when is_map(svcs) and map_size(svcs) != 0 ->
        changeset

      _ ->
        case get_change(changeset, :service) do
          key when is_binary(key) -> changeset
          _ -> add_error(changeset, :service, "can't be blank")
        end
    end
  end
end
