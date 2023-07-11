defmodule IntegrityProofs.Did.PlcLog.Operation do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  @timestamps_opts [type: :utc_datetime, updated_at: false]
  schema "operations" do
    field(:did, :string, primary_key: true)
    field(:cid, :string, primary_key: true)
    field(:operation, :string)
    field(:nullified, :boolean)

    timestamps()
  end

  def changeset(%__MODULE__{} = op, attrs) do
    %__MODULE__{}
    |> cast(attrs, [:did, :cid, :operation, :nullified])
    |> validate_required([:did, :cid, :operation])
    |> validate_inclusion(:operation, ["create", "plc_operation", "plc_tombstone"])
  end
end
