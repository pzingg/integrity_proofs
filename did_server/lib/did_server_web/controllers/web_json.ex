defmodule DidServerWeb.WebJSON do
  def show(%{document: doc}) do
    %{data: doc}
  end

  def info(%{version: version}) do
    %{data: %{version: version, info: "did:web server"}}
  end
end
