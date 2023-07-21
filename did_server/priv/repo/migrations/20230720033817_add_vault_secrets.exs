defmodule DidServer.Repo.Migrations.AddVaultSecrets do
  use Ecto.Migration

  def change do
    create table(:secrets, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :name, :string
      add :description, :text, null: false, default: ""
      add :secret, :text, null: false
      add :key_id, :uuid, null: false
      add :nonce, :string, null: false

      timestamps()
    end

    create unique_index(:secrets, [:name], where: "name IS NOT NULL")

    alter table(:keys) do
      add :secret_name, :string
    end
  end
end
