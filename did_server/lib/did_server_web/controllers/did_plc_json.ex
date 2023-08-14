defmodule DidServerWeb.DidPlcJSON do
  def info(%{info: info}) when is_map(info) do
    info
  end

  def health(%{version: version} = params) do
    error = Map.get(params, :error)

    if is_nil(error) do
      %{version: version, status: "ok"}
    else
      %{version: version, status: "failed", errors: %{detail: error}}
    end
  end

  def did_document(%{document: doc}) when is_map(doc) do
    doc
  end

  def operation(%{operation: op}) when is_map(op) do
    op
  end

  def log(%{operations: ops}) when is_list(ops) do
    ops
  end
end
