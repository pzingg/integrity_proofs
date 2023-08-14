defmodule DidServer.Repo.Migrations.AddUsersTokens do
  use Ecto.Migration

  def change do
    create table(:users_tokens, primary_key: false) do
      add :context, :string, primary_key: true
      add :token, :binary, primary_key: true
      add :sent_to, :string
      add :user_id, references(:users, type: :uuid, on_delete: :delete_all), null: false

      timestamps(updated_at: false)
    end

    create index(:users_tokens, [:user_id])
  end
end
