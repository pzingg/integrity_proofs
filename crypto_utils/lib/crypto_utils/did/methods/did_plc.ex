defmodule CryptoUtils.Did.Methods.DidPlc do
  @moduledoc """
  Handler for the did:key method.
  """

  @behaviour CryptoUtils.Did.Method
  @behaviour CryptoUtils.Did.Resolver

  alias CryptoUtils.Did
  alias CryptoUtils.Did.{DocumentMetadata, ResolutionMetadata}

  @impl CryptoUtils.Did.Method
  def name() do
    "plc"
  end

  @impl CryptoUtils.Did.Method
  def to_resolver() do
    __MODULE__
  end

  @impl CryptoUtils.Did.Method
  def validate(%{method_specific_id: base32_cid} = parsed, _) do
    if byte_size(base32_cid) == 24 && Regex.match?(~r/[^a-z2-7]/, base32_cid) do
      {:ok, parsed}
    else
      :error
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
    case did_plc_uri(did, opts) do
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
  Resolve the URL for a did:plc identifier.
  """
  def did_plc_uri(did, opts \\ [])

  def did_plc_uri(did, opts) when is_binary(did) do
    try do
      opts = Keyword.put(opts, :expected_did_methods, [:plc])
      parsed_did = Did.parse_did!(did, opts)
      did_plc_uri(parsed_did, opts)
    rescue
      _ -> {:error, "invalid did:plc #{did}"}
    end
  end

  def did_plc_uri(%{did_string: identifier}, opts) do
    uri = Keyword.get(opts, :plc_server_url, "https://plc.directory") |> URI.parse()
    {:ok, %URI{uri | path: "/#{identifier}"}}
  end

  defp error_result(error) do
    {:error, {%ResolutionMetadata{error: error}, nil, nil}}
  end
end
