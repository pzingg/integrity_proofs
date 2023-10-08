defmodule CryptoUtils.Did.Methods.DidWeb do
  @moduledoc """
  Handler for the did:web method.
  """

  @behaviour CryptoUtils.Did.Method
  @behaviour CryptoUtils.Did.Resolver

  alias CryptoUtils.Did
  alias CryptoUtils.Did.{DocumentMetadata, ResolutionMetadata}

  @impl CryptoUtils.Did.Method
  def name() do
    "web"
  end

  @impl CryptoUtils.Did.Method
  def to_resolver() do
    __MODULE__
  end

  @impl CryptoUtils.Did.Method
  def validate(%{method_specific_id: method_specific_id} = parsed, options) do
    [host_port | path_parts] = String.split(method_specific_id, ":")

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
        :error

      is_integer(port) && (port == 0 || port > 65535) ->
        :error

      true ->
        scheme = Keyword.get(options, :scheme, "https")

        port =
          case {scheme, port} do
            {"http", 80} -> nil
            {"https", 443} -> nil
            {_, p} -> p
          end

        {:ok, Map.merge(parsed, %{scheme: scheme, host: host, port: port, path: path})}
    end
  end

  @impl CryptoUtils.Did.Resolver
  def resolve(did, opts) do
    with {:ok, {res_meta, doc_data, doc_meta}} <- resolve_representation(did, opts),
         {:ok, doc} <- Jason.decode(doc_data) do
      # https://www.w3.org/TR/did-core/#did-resolution-metadata
      # contentType - "MUST NOT be present if the resolve function was called"
      {:ok, {%ResolutionMetadata{res_meta | content_type: nil}, doc, doc_meta}}
    else
      {:error, reason} ->
        error_result(reason)
    end
  end

  @impl CryptoUtils.Did.Resolver
  def resolve_representation(did, opts) do
    case did_web_uri(did) do
      {:ok, uri} ->
        client = Keyword.get(opts, :client, CryptoUtils.HttpClient)
        # TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security
        accept = Keyword.get(opts, :accept, "application/json")

        opts =
          opts
          |> Keyword.put(:headers, [{"accept", accept}])
          |> Keyword.put(:method, :get)

        case client.fetch(URI.to_string(uri), opts) do
          {:ok, body} ->
            # TODO: set document created/updated metadata from HTTP headers?
            res_meta = %ResolutionMetadata{content_type: "application/did+ld+json"}
            doc_meta = %DocumentMetadata{}

            {:ok, {res_meta, body, doc_meta}}

          {:error, _, status_code} ->
            {:error, "Error sending HTTP request #{status_code}"}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  Resolve the URL for a did:web identifier.

  The method specific identifier MUST match the common name used in
  the SSL/TLS certificate, and it MUST NOT include IP addresses.
  A port MAY be included and the colon MUST be percent encoded to
  prevent a conflict with paths. Directories and subdirectories MAY
  optionally be included, delimited by colons rather than slashes.

  web-did = "did:web:" domain-name
  web-did = "did:web:" domain-name * (":" path)
  """
  def did_web_uri(did, opts \\ [])

  def did_web_uri(did, opts) when is_binary(did) do
    try do
      opts = Keyword.put(opts, :expected_did_methods, [:web])
      parsed_did = Did.parse_did!(did, opts)
      did_web_uri(parsed_did, opts)
    rescue
      _ -> {:error, "invalid did:web #{did}"}
    end
  end

  def did_web_uri(parsed_did, _opts) when is_map(parsed_did) do
    # TODO:
    # - Validate domain name: alphanumeric, hyphen, dot. no IP address.
    # - Ensure domain name matches TLS certificate common name
    # - Support punycode?
    # - Support query strings?

    {:ok,
     %URI{
       scheme: parsed_did.scheme,
       host: parsed_did.host,
       port: parsed_did.port,
       path: parsed_did.path
     }}
  end

  defp error_result(reason) do
    {:error, {%ResolutionMetadata{error: reason}, nil, nil}}
  end
end
