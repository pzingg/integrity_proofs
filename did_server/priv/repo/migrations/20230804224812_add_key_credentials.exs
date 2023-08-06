defmodule DidServer.Repo.Migrations.AddKeyCredentials do
  use Ecto.Migration

  def change do
    create table(:credentials, primary_key: false) do
      add :raw_id, :string, primary_key: true
      add :cose_key, :map, null: false
      add :aaguid, :string
      add :user_id, references(:users_keys, type: :uuid, on_delete: :delete_all), null: false

      timestamps(updated_at: false)
    end
  end
end
