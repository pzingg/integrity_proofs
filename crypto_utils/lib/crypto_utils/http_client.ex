defmodule CryptoUtils.HttpClient do
  @moduledoc """
  Makes HTTP requests with optional rewriting, and
  resolves both "web" and "plc" dids.
  """

  require Logger

  @doc """
  Makes HTTP requests, using the `Req` library.

  `opts` include:

    * `:method` - `:get` (default) or `:post`
    * `:body` - for `:post` requests, the body of the request.
    * `:content_type` - for `:post` requests, the mime type (default "text/plain")
    * `:headers` - a map of request headers (keys must be lowercase strings)
    * `:rewrite_patterns` - for testing, rewrite rules
    * `:opts` - other options to pass to the `Req` request.

  On success, returns `{:ok, body}`. The body is not automatically
  decoded.

  On error, returns `{:error, {reason, http_status_code}}`.
  """
  @impl true
  def fetch(url, opts) do
    {method, opts} = Keyword.pop(opts, :method, :get)
    {user_agent, opts} = Keyword.pop(opts, :user_agent, "integrity-proofs.req")
    {rewrite_patterns, opts} = Keyword.pop(opts, :rewrite_patterns, [])
    url = maybe_rewrite(url, rewrite_patterns)
    opts = Keyword.merge(opts, url: url, decode_body: false)
    req = Req.new()

    result =
      case method do
        :get ->
          headers = %{"user-agent" => user_agent}
          opts = Keyword.update(opts, :headers, headers, fn h -> Map.merge(headers, h) end)
          Req.get(req, opts)

        :post ->
          content_type = Keyword.get(opts, :content_type, "plain/text")
          headers = %{"content-type" => content_type, "user-agent" => user_agent}
          opts = Keyword.update(opts, :headers, headers, fn h -> Map.merge(headers, h) end)
          Req.post(req, opts)
      end

    case result do
      {:ok, %Req.Response{status: status, body: body, headers: headers}} ->
        if status in 200..299 do
          {:ok, body}
        else
          {:error, body, status}
        end

      {:error, ex} ->
        {:error, ex, 999}
    end
  end

  def maybe_rewrite(url, [_ | _] = patterns) do
    case Enum.find(patterns, fn {re, _} -> Regex.match?(re, url) end) do
      {re, replacement} ->
        location = Regex.replace(re, url, replacement)
        Logger.debug("crypto_utils http client rewrite #{url} -> #{location}")
        location

      _ ->
        url
    end
  end

  def maybe_rewrite(url, _), do: url
end
