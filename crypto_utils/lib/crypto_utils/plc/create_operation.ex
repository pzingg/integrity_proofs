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
  end

  def parse(params) when is_list(params), do: Map.new(params) |> parse()

  def parse(params) when is_map(params) do
    case changeset(%__MODULE__{}, params) |> apply_action(:create) do
      {:ok, %{type: type} = op} ->
        case type do
          "create" ->
            {:ok,
             {%CreateParams{
                did: op.did,
                type: "plc_operation",
                prev: op.prev,
                sig: op.sig,
                verification_methods: %{"atproto" => op.signingKey},
                rotation_keys: [op.recoveryKey],
                also_known_as: [CryptoUtils.ensure_atproto_prefix(op.handle)],
                services: %{
                  "atproto_pds" => %{
                    "type" => "AtprotoPersonalDataServer",
                    "endpoint" => CryptoUtils.ensure_http_prefix(op.service)
                  }
                }
              }, op.signer}}

          "plc_operation" ->
            {:ok,
             {%CreateParams{
                did: op.did,
                type: "plc_operation",
                prev: op.prev,
                sig: op.sig,
                verification_methods: op.verificationMethods,
                rotation_keys: op.rotationKeys,
                also_known_as: op.alsoKnownAs,
                services: op.services
              }, op.signer}}

          "plc_tombstone" ->
            {:ok,
             {%CreateParams{did: op.did, type: "plc_tombstone", prev: op.prev, sig: op.sig},
              op.signer}}
        end

      error ->
        error
    end
  end

  def changeset(op, attrs \\ %{}) do
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
        :services
      ])

    changeset
    |> validate_op()
  end

  defp validate_op(changeset) do
    case {get_change(changeset, :signingKey), get_change(changeset, :type)} do
      {_, "plc_tombstone"} ->
        validate_required(changeset, [:prev])

      {_, "plc_operation"} ->
        validate_required(changeset, [:verificationMethods, :rotationKeys, :alsoKnownAs])

      {_, "create"} ->
        validate_required(changeset, [:signingKey, :recoveryKey, :handle, :service])

      {signing_key, nil} when is_binary(signing_key) ->
        changeset
        |> put_change(:type, "create")
        |> validate_required([:signingKey, :recoveryKey, :handle, :service])

      _ ->
        add_error(changeset, :type, "is invalid",
          validation: :inclusion,
          enum: ["create", "plc_operation", "plc_tombstone"]
        )
    end
  end
end
