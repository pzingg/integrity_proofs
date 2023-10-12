defmodule CryptoUtils.HttpClient do
  @moduledoc """
  Makes HTTP requests with optional rewriting, and
  resolves both "web" and "plc" dids.
  """
  @behaviour CryptoUtils.Fetcher

  require Logger

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
    user_agent = Keyword.get(opts, :user_agent, "integrity-proofs.httpc")
    headers = Keyword.get(opts, :headers, [])

    headers =
      [{"user-agent", user_agent} | headers]
      |> Enum.map(fn {key, value} -> {String.to_charlist(key), String.to_charlist(value)} end)

    content_type = Keyword.get(opts, :content_type, "plain/text") |> String.to_charlist()
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
end
