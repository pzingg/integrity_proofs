defmodule DidServer.Repo.Migrations.AddVaultSecrets do
  use Ecto.Migration

  def change do
    create table(:secrets, primary_key: false) do
      add :id, :uuid, primary_key: true
      add :name, :text
      add :description, :text, null: false, default: ""
      add :secret, :text, null: false
      add :key_id, :uuid, null: false
      add :nonce, :string, null: false

      timestamps()
    end

    create unique_index(:secrets, [:name], where: "name IS NOT NULL")

    create table(:keys_secrets) do
      add :did_id, references(:dids, column: :did, type: :string, on_delete: :delete_all), null: false
      add :secret_id, references(:secrets, type: :binary_id, on_delete: :delete_all), null: false
      add :context, :string, null: false

      timestamps()
    end

    create index(:keys_secrets, [:did_id])
    create index(:keys_secrets, [:secret_id])
    create unique_index(:keys_secrets, [:context, :secret_id])
  end
end
