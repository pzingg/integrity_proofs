defmodule DidServer.Log.Operation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @timestamps_opts [type: :naive_datetime_usec, updated_at: false]
  schema "operations" do
    field(:did, :string, primary_key: true)
    field(:cid, :string, primary_key: true)
    field(:operation, :string)
    field(:nullified, :boolean)
    field(:op_data, :map, default: %{}, virtual: true)
    field(:prev, :string, virtual: true)
    field(:nullified_cids, {:array, :string}, default: [], virtual: true)
    field(:password, :string, virtual: true)

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

  def also_known_as(%__MODULE__{op_data: %{"alsoKnownAs" => aka}}) do
    aka
  end

  def also_known_as(%__MODULE__{operation: op_json}) do
    %{"alsoKnownAs" => aka} = Jason.decode!(op_json)
    aka
  end

  def decode(%__MODULE__{operation: op_json} = op) do
    %__MODULE__{op | op_data: Jason.decode!(op_json)}
  end

  def to_data(%__MODULE__{operation: op_json}) do
    %{"type" => type} = data = Jason.decode!(op_json)

    if type == "plc_tombstone" do
      nil
    else
      prev = Map.fetch!(data, "prev")

      ["verificationMethods", "rotationKeys", "alsoKnownAs", "services", "sig"]
      |> Enum.reduce(%{"type" => type, "prev" => prev}, fn field, acc ->
        case Map.get(data, field) do
          nil -> acc
          value -> Map.put(acc, field, value)
        end
      end)
    end
  end

  def changeset(%__MODULE__{} = op, attrs) do
    op
    |> cast(attrs, [:did, :cid, :operation, :nullified, :prev, :nullified_cids, :password])
    |> validate_required([:did, :cid, :operation])
    |> set_nullified()
  end

  def changeset_raw(%__MODULE__{} = op, attrs) do
    op
    |> cast(attrs, [
      :did,
      :cid,
      :operation,
      :nullified,
      :inserted_at,
      :prev,
      :nullified_cids,
      :password
    ])
    |> validate_required([:did, :cid, :operation, :nullified, :inserted_at])
    |> set_nullified()
  end

  def set_nullified(changeset) do
    if changed?(changeset, :nullified) do
      changeset
    else
      not_nullified = get_change(changeset, :nullified_cids, []) |> Enum.empty?()
      put_change(changeset, :nullified, !not_nullified)
    end
  end
end
