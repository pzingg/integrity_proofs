defmodule Integrity.Did.PlcRepo.Migrations.AddOperations do
  use Ecto.Migration

  def change do
    create table(:dids, primary_key: false) do
      add :did, :string, primary_key: true
      add :hashed_password, :string, null: false

      timestamps()
    end

    create table(:operations, primary_key: false) do
      add :did, :string, primary_key: true
      add :cid, :string, primary_key: true
      add :operation, :text
      add :nullified, :boolean, default: false

      timestamps(type: :naive_datetime_usec, updated_at: false)
    end

    create index(:operations, :inserted_at)
  end
end
