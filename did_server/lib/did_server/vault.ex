defmodule DidServer.Vault do
  @moduledoc """
  The Vault context.
  """

  import Ecto.Query, warn: false
  alias DidServer.Repo

  alias DidServer.Vault.Secret

  def get_secret!(name) do
    Repo.get_by!(Secret, name: name)
  end

  def create_secret(name, secret_string) do
    Secret.changeset(%Secret{}, %{name: name, secret: secret_string})
    |> Repo.insert(on_conflict: {:replace, [:secret]}, conflict_target: :name)
  end

  def update_secret(name, secret_string) do
    with {:ok, secret} <- Repo.get_by(Secret, name: name) do
      Secret.update_changeset(secret, %{secret: secret_string})
      |> Repo.update()
    end
  end

  def delete_secret(name) do
    with {:ok, secret} <- Repo.get_by(Secret, name: name) do
      Repo.delete(secret)
    end
  end
end
