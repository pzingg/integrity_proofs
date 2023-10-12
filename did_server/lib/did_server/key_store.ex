defmodule DidServer.KeyStore do
  use Agent

  @doc """
  Starts a new bucket.
  """
  def start_link(_opts) do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @doc """
  Gets the number of entrie in the store.
  """
  def size() do
    Agent.get(__MODULE__, &map_size(&1))
  end

  @doc """
  Gets a `{public_key, private_key}` tuple from the store.
  """
  def first() do
    case Agent.get(__MODULE__, fn state -> state |> Map.to_list() |> hd() end) do
      nil -> {:error, "No keys"}
      entry -> {:ok, entry}
    end
  end

  @doc """
  Gets a value from the store by `key`.
  """
  def get(key) do
    Agent.get(__MODULE__, &Map.get(&1, key))
  end

  @doc """
  Puts the `value` for the given `key` in the store.
  """
  def put(key, value) do
    Agent.update(__MODULE__, &Map.put(&1, key, value))
  end

  @doc """
  Removes the `value` for the given `key` in the store.
  """
  def delete(key) do
    Agent.update(__MODULE__, &Map.delete(&1, key))
  end
end
