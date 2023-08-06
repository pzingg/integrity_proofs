defmodule DidServer.Repo.Migrations.AddUsers do
  use Ecto.Migration

  def change do
    execute("CREATE EXTENSION IF NOT EXISTS citext", "")

    create table(:users, primary_key: false) do
      add(:id, :uuid, primary_key: true)
      add(:email, :citext, null: false)
      add(:username, :citext, null: false)
      add(:domain, :citext, null: false)
      # add :hashed_password, :string, null: false
      add(:confirmed_at, :naive_datetime)
      timestamps()
    end

    create(unique_index(:users, [:email]))
    create(unique_index(:users, [:username, :domain]))
  end
end
