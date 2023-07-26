defmodule DidServerWeb.AccountJSON do
  def actor(%{user: user}) do
    user
    |> Map.from_struct()
    |> Map.take([:username, :domain, :display_name, :description])
  end

  def profile(%{user: user}) do
    user
    |> Map.from_struct()
    |> Map.take([:username, :domain, :display_name, :description])
  end
end
