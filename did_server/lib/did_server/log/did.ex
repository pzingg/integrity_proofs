defmodule IntegrityProofs.Did.PlcLog.Did do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key false
  schema "dids" do
    field(:did, :string, primary_key: true)
  end

  def changeset(%__MODULE__{} = did, attrs) do
    %__MODULE__{}
    |> cast(attrs, [:did])
    |> validate_required([:did])
  end
end
