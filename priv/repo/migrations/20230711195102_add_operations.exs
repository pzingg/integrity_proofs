defmodule IntegrityProofs.Repo.Migrations.AddOperations do
  use Ecto.Migration

  def change do
    create table(:operations, primary_key: false) do
      add :did, :string, primary_key: true
      add :cid, :string, primary_key: true
      add :operation, :string, null: false
      add :nullified, :boolean, default: false

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create table(:dids, primary_key: false) do
      add :did, :string, primary_key: true
    end
  end
end
