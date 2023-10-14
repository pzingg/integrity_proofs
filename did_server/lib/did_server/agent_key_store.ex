defmodule DidServer.AgentKeyStore do
  use Agent

  @behaviour DidServer.KeyStore

  @doc """
  Starts a new keystore, creating `:system_keys` (integer) system keys.
  """
  def start_link(opts) do
    Agent.start_link(fn -> create_system_keys(opts) end, name: __MODULE__)
  end

  @doc """
  Gets the number of entries in the store.
  """
  @impl DidServer.KeyStore
  def size(user) do
    Agent.get(__MODULE__, fn state -> get_user_keys(user, state) |> map_size() end)
  end

  @doc """
  List all the `{public_key, private_key}` tuple entries in the store.
  """
  @impl DidServer.KeyStore
  def list(user) do
    Agent.get(__MODULE__, fn state -> get_user_keys(user, state) |> Map.to_list() end)
  end

  @doc """
  Gets a `{public_key, private_key}` tuple from the store.
  """
  @impl DidServer.KeyStore
  def first(user) do
    case Agent.get(__MODULE__, fn state -> get_user_keys(user, state) |> Map.to_list() |> hd() end) do
      nil -> {:error, "No keys"}
      entry -> {:ok, entry}
    end
  end

  @doc """
  Gets a value from the store by `key`.
  """
  @impl DidServer.KeyStore
  def get(user, key) do
    Agent.get(__MODULE__, fn state -> get_user_keys(user, state) |> Map.get(key) end)
  end

  @doc """
  Puts the `value` for the given `key` in the store.
  """
  @impl DidServer.KeyStore
  def put(user, key, value) do
    Agent.update(__MODULE__, fn state ->
      Map.update(state, user, %{key => value}, fn user_keys -> Map.put(user_keys, key, value) end)
    end)
  end

  @doc """
  Removes the `value` for the given `key` in the store.
  """
  @impl DidServer.KeyStore
  def delete(user, key) do
    Agent.update(__MODULE__, fn state ->
      user_keys = get_user_keys(user, state) |> Map.delete(key)

      if map_size(user_keys) == 0 do
        Map.delete(state, user)
      else
        Map.put(state, user, user_keys)
      end
    end)
  end

  defp get_user_keys(user, state) do
    Map.get(state, user, %{})
  end

  defp create_system_keys(opts) do
    n_keys = Keyword.get(opts, :system_keys, 2)

    system_keys =
      Enum.map(1..n_keys//1, fn _i ->
        {did_key, private_key_pem, _, _} =
          CryptoUtils.Keys.generate_keypair(:ed25519, :did_key, :pem)

        {did_key, private_key_pem}
      end)
      |> Map.new()

    %{system: system_keys}
  end
end
