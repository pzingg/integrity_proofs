defmodule DidServerWeb.DidWebJSON do
  def show(%{document: doc}) when is_map(doc) do
    doc
  end

  def info(%{version: version}) do
    %{data: %{version: version, detail: "did:web server"}}
  end
end
