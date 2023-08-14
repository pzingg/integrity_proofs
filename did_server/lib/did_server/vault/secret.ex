defmodule DidServer.Vault.Secret do
  use Ecto.Schema
  import Ecto.Changeset

  @nonce_size 32

  @primary_key {:id, :binary_id, autogenerate: true}
  schema "secrets" do
    field :name, :string
    field :description, :string
    field :secret, :string, redact: true
    field :key_id, Ecto.UUID
    field :nonce, :string

    timestamps()
  end

  def changeset(%__MODULE__{} = secret, attrs) do
    secret
    |> cast(attrs, [:name, :description, :secret, :key_id, :nonce])
    |> validate_required([:secret])
    |> unique_constraint(:name)
    |> generate_key_id_and_nonce()
  end

  def update_changeset(%__MODULE__{} = secret, attrs) do
    secret
    |> cast(attrs, [:description, :secret, :key_id, :nonce])
    |> validate_required([:secret])
    |> generate_key_id_and_nonce()
  end

  defp generate_key_id_and_nonce(changeset) do
    changeset =
      if is_nil(get_change(changeset, :key_id)) do
        put_change(changeset, :key_id, Ecto.UUID.generate())
      else
        changeset
      end

    if is_nil(get_change(changeset, :nonce)) do
      nonce = :crypto.strong_rand_bytes(@nonce_size) |> Multibase.encode!(:base32_lower)
      put_change(changeset, :nonce, nonce)
    else
      changeset
    end
  end
end
