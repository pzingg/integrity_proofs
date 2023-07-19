defmodule CryptoUtils.Plc.UpdateOperation do
  @moduledoc """
  Parsing and validating inputs for updating a did:plc operation.

  Inputs could be for Bluesky v1 "create" , "plc_operation", or "plc_tombstone".
  """

  use Ecto.Schema
  import Ecto.Changeset

  embedded_schema do
    field(:did, :string)
    field(:type, :string)
    field(:signer, {:array, :string})
    field(:signingKey, :string)
    field(:handle, :string)
    field(:pds, :string)
    field(:rotationKeys, {:array, :string})
  end

  def parse(params) when is_list(params), do: Map.new(params) |> parse()

  def parse(params) when is_map(params) do
    changeset(%__MODULE__{}, params) |> apply_action(:update)
  end

  def changeset(op, attrs \\ %{}) do
    changeset =
      op
      |> cast(attrs, [
        :did,
        :type,
        :signer,
        :signingKey,
        :handle,
        :pds,
        :rotationKeys
      ])

    changeset
    |> validate_required([:did, :signer])
    |> put_type()
  end

  defp put_type(changeset) do
    case get_change(changeset, :type) do
      nil ->
        put_change(changeset, :type, "plc_operation")

      type ->
        if type in ["plc_operation", "plc_tombstone"] do
          changeset
        else
          add_error(changeset, :type,
            validation: :inclusion,
            enum: ["plc_operation", "plc_tombstone"]
          )
        end
    end
  end
end
