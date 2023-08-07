defmodule DidServer.Repo.Migrations.AddAccountProfileFields do
  use Ecto.Migration

  def change do
    alter table(:accounts) do
      add :display_name, :string
      add :description, :text
      add :avatar, :binary
      add :avatar_mime_type, :string
      add :banner, :binary
      add :banner_mime_type, :string
    end
  end
end
