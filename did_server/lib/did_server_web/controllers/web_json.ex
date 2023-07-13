defmodule DidServerWeb.WebJSON do
  def info(%{version: version}) do
    %{data: %{version: version, info: "did:web server"}}
  end
end
