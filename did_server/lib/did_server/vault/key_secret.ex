defmodule DidServer.Vault.KeySecret do
  use Ecto.Schema
  import Ecto.Changeset

  schema "keys_secrets" do
    field :context, :string

    belongs_to :did, DidServer.Log.Did, references: :did, foreign_key: :did_key
    belongs_to :secret, DidServer.Vault.Secret
    timestamps()
  end

  def changeset(%__MODULE__{} = key_secret, attrs) do
    key_secret
    |> cast(attrs, [:context, :did, :secret_id])
    |> validate_required([:context, :did, :secret_id])
    |> unique_constraint([:context, :secret_id])
  end
end
