defmodule Integrity.Did.PlcRepo.Migrations.AddOperations do
  use Ecto.Migration

  def change do
    create table(:keys, primary_key: false) do
      add :did, :string, primary_key: true
      add :method, :string, null: false
      add :hashed_password, :string

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
