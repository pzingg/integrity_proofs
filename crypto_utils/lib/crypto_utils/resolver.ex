defmodule CryptoUtils.Resolver do
  @moduledoc """
  Makes HTTP requests with optional rewriting, and
  resolves both "web" and "plc" dids.
  """
  @behaviour CryptoUtils.Fetcher

  alias CryptoUtils.Did

  @doc """
  Makes HTTP requests. The `:rewrite_patterns` option
  is a list of 2-tuples, representing the `regex` and `replacement`
  arguments to `Regex.replace/4`. The `regex` is matched against
  the entire URL, with the query string and fragment removed.

  If a pattern matches, the URL is rewritten, and no further
  rewrites are attempted.
  """
  @impl true
  def fetch(url, opts) do
    httpc_http_opts = Keyword.get(opts, :http_opts, [])
    httpc_opts = Keyword.get(opts, :opts, [])
    headers = Keyword.get(opts, :headers, [])
    content_type = Keyword.get(opts, :content_type, "plain/text")
    body = Keyword.get(opts, :body, "OK")

    url = maybe_rewrite(url, opts)

    opts
    |> Keyword.get(:method, :get)
    |> case do
      :post ->
        :httpc.request(:post, {url, headers, content_type, body}, httpc_http_opts, httpc_opts)

      :get ->
        :httpc.request(:get, {url, headers}, httpc_http_opts, httpc_opts)
    end
    |> case do
      {:ok, {{_, 200, _}, _headers, body}} -> {:ok, to_string(body)}
      {:ok, {{_, status_code, _}, _headers, body}} -> {:error, to_string(body), status_code}
      {:error, error} -> {:error, error, 999}
    end
  end

  def maybe_rewrite(url, opts) do
    with [_ | _] = patterns <- Keyword.get(opts, :rewrite_patterns),
         {re, replacement} <- Enum.find(patterns, fn {re, _} -> Regex.match?(re, url) end) do
      Regex.replace(re, url, replacement)
    else
      _ ->
        url
    end
  end

  def resolve_did(did, opts) do
    try do
      %{method: method} = parsed_did = Did.parse_did!(did, expected_did_methods: [:web, :plc])

      case method do
        :web -> resolve_did_web(parsed_did, opts)
        :plc -> resolve_did_plc(parsed_did, opts)
      end
    rescue
      error ->
        IO.inspect(error)
        {:error, "invalid did #{did}"}
    end
  end

  def resolve_did_web(parsed_did, opts) do
    fetcher = Keyword.get(opts, :fetcher, __MODULE__)

    url =
      %URI{
        scheme: parsed_did.scheme,
        host: parsed_did.host,
        port: parsed_did.port,
        path: parsed_did.path
      }
      |> URI.to_string()

    # opts = Keyword.put(opts, :headers, [{"accept", "application/json"}])

    case fetcher.fetch(url, opts) do
      {:ok, body} -> Jason.decode(body)
      error -> error
    end
  end

  def resolve_did_plc(parsed_did, opts) do
    fetcher = Keyword.get(opts, :fetcher, __MODULE__)
    uri = Keyword.get(opts, :plc_server_url, "https://plc.directory") |> URI.parse()
    url = %URI{uri | path: "/#{parsed_did.did_string}"} |> URI.to_string()
    # opts = Keyword.put(opts, :headers, [{"accept", "application/json"}])

    case fetcher.fetch(url, opts) do
      {:ok, body} -> Jason.decode(body)
      error -> error
    end
  end
end
