defmodule DidServer.Repo.Migrations.AddAccounts do
  use Ecto.Migration

  def change do
    execute("CREATE EXTENSION IF NOT EXISTS citext", "")

    create table(:accounts, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :email, :citext, null: false
      add :username, :citext, null: false
      add :domain, :citext, null: false
      # add :hashed_password, :string, null: false
      add :confirmed_at, :naive_datetime
      timestamps()
    end

    create(unique_index(:accounts, [:email]))
    create(unique_index(:accounts, [:username, :domain]))
  end
end
