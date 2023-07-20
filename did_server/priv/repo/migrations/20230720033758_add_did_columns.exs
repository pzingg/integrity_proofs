defmodule DidServer.Repo.Migrations.AddDidColumns do
  use Ecto.Migration

  def change do
    alter table(:dids) do
      add :hashed_password, :string, null: false
    end

    alter table(:users) do
      remove :hashed_password
    end
  end
end
