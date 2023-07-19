defmodule DidServerWeb.PlcJSON do
  def info(%{version: version}) do
    %{data: %{version: version, details: "did:plc server"}}
  end

  def show(%{document: doc}) do
    %{data: doc}
  end

  def new(%{did: did}) do
    %{data: %{did: did, created: true}}
  end

  def health(%{version: version} = params) do
    error = Map.get(params, :error)

    if is_nil(error) do
      %{data: %{version: version, status: "ok"}}
    else
      %{data: %{version: version}, errors: %{detail: error}}
    end
  end
end
