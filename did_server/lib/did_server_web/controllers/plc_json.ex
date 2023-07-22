defmodule DidServerWeb.PlcJSON do
  def info(%{info: info}) do
    %{data: info}
  end

  def health(%{version: version} = params) do
    error = Map.get(params, :error)

    if is_nil(error) do
      %{data: %{version: version, status: "ok"}}
    else
      %{data: %{version: version}, errors: %{detail: error}}
    end
  end

  def new(%{did: did}) do
    %{data: %{did: did, created: true}}
  end

  def did_document(%{document: doc}) do
    %{data: doc}
  end

  def operation(%{operation: op}) do
    %{data: op}
  end

  def log(%{operations: ops}) do
    %{data: ops}
  end
end
