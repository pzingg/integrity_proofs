defmodule DidServerWeb.PlcJSON do
  def info(%{version: version}) do
    %{data: %{version: version, info: "did:plc server"}}
  end

  def health(%{version: version} = params) do
    error = Map.get(params, :error)

    if is_nil(error) do
      %{data: %{version: version, status: "ok"}}
    else
      %{data: %{version: version}, error: error}
    end
  end
end
