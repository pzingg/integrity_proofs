defmodule DidServer.Identities.EctoCoseKey do
  @moduledoc """
  A "cose_key" has integer keys and values that are non-UTF8 binaries.
  So we Base64 encode the values before sending them into the database.
  """

  use Ecto.Type
  def type, do: :map

  # Provide custom casting rules.
  # Only accept casting maps.
  def cast(data) when is_map(data), do: {:ok, data}

  # Cast strings into the decoded map to be used at runtime.
  def cast(encoded_json) when is_binary(encoded_json) do
    case Jason.decode(encoded_json) do
      {:ok, data} when is_map(data) -> load(data)
      _ -> :error
    end
  end

  # Everything else is a failure though
  def cast(_), do: :error

  # When loading data from the database, as long as it's a map,
  # we just put the data back into a map, but decode the bytes in
  # the map values.
  def load(data) when is_map(data) do
    decoded_data =
      data
      |> Enum.map(fn
        {key, val} when is_binary(val) -> {to_integer_key(key), Base.url_decode64!(val, padding: false)}
        {key, val} -> {to_integer_key(key), val}
      end)
      |> Map.new()

    {:ok, decoded_data}
  end

  # When dumping data to the database, we *expect* a map,
  # but any value could be inserted into the schema struct at runtime,
  # so we need to guard against them.
  # Apparently Postgres will convert integer keys into strings.
  def dump(data) when is_map(data) do
    encoded_data =
      data
      |> Enum.map(fn
        {key, val} when is_binary(val) -> {key, Base.url_encode64(val, padding: false)}
        {key, val} -> {key, val}
      end)
      |> Map.new()

    {:ok, encoded_data}
  end

  def dump(_), do: :error

  defp to_integer_key(i) when is_integer(i), do: i
  defp to_integer_key(s) when is_binary(s), do: String.to_integer(s)
end
