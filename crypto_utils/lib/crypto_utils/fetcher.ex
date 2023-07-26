defmodule CryptoUtils.Fetcher do
  @moduledoc """
  A behaviour for executing or mocking synchronous HTTP requests.
  """

  @doc """
  Fetches a url.

  `opts` include:

    * `:method` - `:get` (default) or `:post`
    * `:test_conn` - a `Plug.Conn` struct set up by ExUnit.
    * `:rewrite_patterns` - a list of patterns to rewrite URLs.
    * `:body` - for `:post` requests, the body of the request.
    * `:content_type` - the content type of the specified request body.
    * `:headers` - a list of header tuples.
    * `:http_opts` - HTTP options to pass to the `:httpc` request.
    * `:opts` - other options to pass to the `:httpc` request.

  On success, returns `{:ok, body}`.

  On error, returns `{:error, {reason, http_status_code}}`.
  """
  @callback fetch(url :: String.t(), opts :: Keyword.t()) ::
              {:ok, term()} | {:error, {reason :: term, status_code :: non_neg_integer()}}
end
