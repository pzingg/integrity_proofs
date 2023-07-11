defmodule IntegrityProofs.Did.PlcRepo do
  use Ecto.Repo,
    otp_app: :integrity_proofs,
    adapter: Ecto.Adapters.Postgres
end
