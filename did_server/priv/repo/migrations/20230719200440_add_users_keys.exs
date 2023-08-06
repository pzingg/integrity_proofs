defmodule DidServer.Repo.Migrations.AddUsersDids do
  use Ecto.Migration

  def change do
    create table(:users_keys, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false

      add :key_id, references(:keys, type: :string, column: :did, on_delete: :delete_all),
        null: false

      timestamps()
    end

    create unique_index(:users_keys, [:user_id, :key_id])
    create index(:users_keys, [:user_id])
    create index(:users_keys, [:key_id])
  end
end
