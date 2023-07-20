defmodule DidServerWeb.Utils do
  @moduledoc false
  @doc """
  Removes :authority, :userinfo, and :port after parsing a URI.
  Leaves :scheme, :host, :path, :query, and :fragment unchanged.
  """
  def to_uri(url) when is_binary(url) do
    %URI{port: port} = uri = URI.parse(url)

    port =
      case port do
        80 -> nil
        443 -> nil
        p when is_integer(p) -> p
        _ -> nil
      end

    %URI{uri | authority: nil, userinfo: nil, port: port}
  end

  @doc """
  Removes :authority, :userinfo, :port, :query, and :fragment from a URI.
  Leaves :scheme and :host unchanged.
  Sets :path if `path` is not nil, otherwise leaves it unchanged.
  """
  def base_uri(uri, path \\ nil)

  def base_uri(uri, path) when is_binary(uri) do
    to_uri(uri) |> base_uri(path)
  end

  def base_uri(%URI{} = uri, path) when is_binary(path) do
    %URI{uri | path: path, authority: nil, fragment: nil, query: nil, userinfo: nil}
  end

  def base_uri(%URI{} = uri, nil) do
    %URI{uri | authority: nil, fragment: nil, query: nil, userinfo: nil}
  end

  def http_uri?(%URI{scheme: scheme, host: host, path: path} = _uri) do
    Enum.member?(["http", "https"], scheme) && !is_nil(host) && host != "" &&
      !is_nil(path) && String.length(path) > 1
  end
end
