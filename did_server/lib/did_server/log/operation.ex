defmodule DidServer.Log.Operation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @timestamps_opts [type: :utc_datetime_usec, updated_at: false]
  schema "operations" do
    field(:did, :string, primary_key: true)
    field(:cid, :string, primary_key: true)
    field(:operation, :string)
    field(:nullified, :boolean)

    timestamps()
  end

  def tombstone?(%__MODULE__{operation: operation}) do
    %{"type" => type} = Jason.decode!(operation)
    type == "plc_tombstone"
  end

  def to_data(op, did \\ nil)

  def to_data(%__MODULE__{did: op_did, operation: operation}, did) do
    %{"type" => type} = data = Jason.decode!(operation)

    if type == "plc_tombstone" do
      nil
    else
      did = did || op_did

      ["verificationMethods", "rotationKeys", "alsoKnownAs", "services"]
      |> Enum.reduce(%{"type" => type, "did" => did}, fn field, acc ->
        case Map.get(data, field) do
          nil -> acc
          value -> Map.put(acc, field, value)
        end
      end)
    end
  end

  def changeset(%__MODULE__{} = op, attrs) do
    op
    |> cast(attrs, [:did, :cid, :operation, :nullified])
    |> validate_required([:did, :cid, :operation])
  end
end
