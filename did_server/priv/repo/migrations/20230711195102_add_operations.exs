defmodule Integrity.Did.PlcRepo.Migrations.AddOperations do
  use Ecto.Migration

  def change do
    create table(:operations, primary_key: false) do
      add :did, :string, primary_key: true
      add :cid, :string, primary_key: true
      add :operation, :text
      add :nullified, :boolean, default: false

      timestamps(type: :utc_datetime_usec, updated_at: false)
    end

    create index(:operations, :inserted_at)

    create table(:dids, primary_key: false) do
      add :did, :string, primary_key: true
    end
  end
end
