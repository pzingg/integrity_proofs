defmodule DidServer.Repo.Migrations.AddUserProfileFields do
  use Ecto.Migration

  def change do
    alter table(:users) do
      add :display_name, :string
      add :description, :text
      add :avatar, :binary
      add :avatar_mime_type, :string
      add :banner, :binary
      add :banner_mime_type, :string
    end
  end
end
