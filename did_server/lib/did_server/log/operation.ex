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
    field(:op_data, :map, default: %{}, virtual: true)

    timestamps()
  end

  def operation?(%__MODULE__{op_data: %{"type" => type}}) do
    type == "plc_operation"
  end

  def operation?(%__MODULE__{operation: op_json}) do
    %{"type" => type} = Jason.decode!(op_json)
    type == "plc_operation"
  end

  def operation?(%__MODULE__{op_data: %{"type" => type}}) do
    type == "plc_tombstone"
  end

  def tombstone?(%__MODULE__{operation: op_json}) do
    %{"type" => type} = Jason.decode!(op_json)
    type == "plc_tombstone"
  end

  def decode(%__MODULE__{operation: op_json} = op) do
    %__MODULE__{op | op_data: Jason.decode!(op_json)}
  end

  def to_data(op, did \\ nil)

  def to_data(%__MODULE__{did: op_did, operation: op_json}, did) do
    %{"type" => type} = data = Jason.decode!(op_json)

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
