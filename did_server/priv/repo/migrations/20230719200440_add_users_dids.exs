defmodule DidServer.Repo.Migrations.AddUsersDids do
  use Ecto.Migration

  def change do
    create table(:users_dids) do
      add :did, :string, null: false
      add :username, :string, null: false
      add :domain, :string, null: false

      timestamps()
    end

    create index(:users_dids, [:did])
    create index(:users_dids, [:username])
    create index(:users_dids, [:domain])
  end
end
