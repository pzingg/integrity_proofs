defmodule DidServer.Repo.Migrations.AddUsersDids do
  use Ecto.Migration

  def change do
    create table(:users_dids) do
      add :user_id, references(:users, on_delete: :delete_all), null: false

      add :did_key, references(:dids, column: :did, type: :string, on_delete: :delete_all),
        null: false

      timestamps()
    end

    create unique_index(:users_dids, [:user_id, :did_key])
    create index(:users_dids, [:user_id])
    create index(:users_dids, [:did_key])
  end
end
