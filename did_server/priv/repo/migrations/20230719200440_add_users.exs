defmodule DidServer.Repo.Migrations.AddUsers do
  use Ecto.Migration

  def change do
    create table(:users, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :account_id, references(:accounts, type: :uuid, on_delete: :delete_all), null: false

      add :key_id, references(:keys, type: :string, column: :did, on_delete: :delete_all),
        null: false

      timestamps()
    end

    create unique_index(:users, [:account_id, :key_id])
    create index(:users, [:account_id])
    create index(:users, [:key_id])
  end
end
