defmodule CryptoUtils.Plc.UpdateOperation do
  @moduledoc """
  Parsing and validating inputs for updating a did:plc operation.

  Inputs could be for Bluesky v1 "create" , "plc_operation", or "plc_tombstone".
  """

  use Ecto.Schema
  import Ecto.Changeset

  embedded_schema do
    field(:did, :string)
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
        :signer,
        :signingKey,
        :handle,
        :pds,
        :rotationKeys
      ])

    changeset
    |> validate_required([:did, :signer])
  end
end
