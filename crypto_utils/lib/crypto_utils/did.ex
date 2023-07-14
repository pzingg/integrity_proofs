defmodule CryptoUtils.Did do
  @moduledoc """
  Basic did handling.
  """

  alias CryptoUtils.{InvalidDidError, UnexpectedDidMethodError}

  @doc """
  Parse a did
  """
  def parse_did!(identifier, options \\ []) do
    parts = String.split(identifier, ":", parts: 3)

    if Enum.count(parts) != 3 || hd(parts) != "did" do
      raise InvalidDidError, identifier
    end

    [_, method, method_specific_id] = parts
    expected_did_method = Keyword.get(options, :expected_did_method)

    if !is_nil(expected_did_method) && expected_did_method != method do
      raise UnexpectedDidMethodError, method
    end

    parsed = %{
      did_string: identifier,
      method: String.to_existing_atom(method),
      method_specific_id: method_specific_id
    }

    case method do
      "key" ->
        validate_did!(:key, parsed, String.split(method_specific_id, ":"), options)

      "web" ->
        validate_did!(:web, parsed, String.split(method_specific_id, ":"), options)

      _ ->
        raise InvalidDidError, identifier
    end
  end

  defp validate_did!(:key, %{did_string: identifier} = parsed, [multibase_value], _) do
    if String.starts_with?(multibase_value, "z") do
      Map.merge(
        parsed,
        %{
          version: "1",
          multibase_value: multibase_value
        }
      )
    else
      raise InvalidDidError, identifier
    end
  end

  defp validate_did!(:key, %{did_string: identifier} = parsed, [version, multibase_value], _) do
    if String.starts_with?(multibase_value, "z") do
      Map.merge(
        parsed,
        %{
          version: version,
          multibase_value: multibase_value
        }
      )
    else
      raise InvalidDidError, identifier
    end
  end

  defp validate_did!(:web, %{did_string: identifier} = parsed, [host_port | path_parts], options) do
    path =
      if Enum.all?(path_parts, fn part ->
           part != "" && is_nil(Regex.run(~r/\s/, part))
         end) do
        case Enum.join(path_parts, "/") do
          "" -> "/.well-known/did.json"
          p -> "/" <> p <> "/did.json"
        end
      else
        nil
      end

    {host, port, path} =
      URI.decode(host_port)
      |> String.split(":", parts: 2)
      |> case do
        [host] ->
          {host, nil, path}

        [host, port] ->
          case Integer.parse(port) do
            {p, ""} -> {host, p, path}
            _ -> {host, 0, path}
          end
      end

    cond do
      is_nil(path) ->
        raise InvalidDidError, identifier

      is_integer(port) && (port == 0 || port > 65535) ->
        raise InvalidDidError, identifier

      true ->
        scheme = Keyword.get(options, :scheme, "https")

        port =
          case {scheme, port} do
            {"http", 80} -> nil
            {"https", 443} -> nil
            {_, p} -> p
          end

        Map.merge(parsed, %{scheme: scheme, host: host, port: port, path: path})
    end
  end

  defp validate_did!(_, %{did_string: identifier}, _, _) do
    raise InvalidDidError, identifier
  end
end
