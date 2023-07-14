defmodule Integrity.Did do
  @moduledoc """
  Functions to create and resolve DID documents.

  Section references refer to [The did:key Method v0.7](https://w3c-ccg.github.io/did-method-key/)

  See also the [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/)
  """

  @doc """
  For "did:web" and other HTTP-reliant methods, use a resolver to
  fetch and decode a DID document.
  """
  def resolve_did_web!(identifier, options) when is_binary(identifier) do
    CryptoUtils.Did.parse_did!(identifier, options)
    |> resolve_did_web!(options)
  end

  def resolve_did_web!(%{method: :web, did_string: identifier} = parsed_did, options) do
    resolver_module = Keyword.fetch!(options, :web_resolver)

    url =
      %URI{
        scheme: parsed_did.scheme,
        host: parsed_did.host,
        port: parsed_did.port,
        path: parsed_did.path
      }
      |> URI.to_string()

    with {:ok, body} <- apply(resolver_module, :fetch, [url, []]),
         {:ok, document} <- Jason.decode(body) do
      document
    else
      {:error, reason} -> raise DidResolutionError, did: identifier, reason: reason
    end
  end

  def resolve_did_web!(%{method: method, did_string: identifier}, _) do
    raise DidResolutionError, did: identifier, reason: "invalid DID method #{method}"
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
  def did_web_uri(identifier, options \\ []) do
    if String.starts_with?(identifier, "did:web:") do
      parsed_did = CryptoUtils.Did.parse_did!(identifier, options)

      {:ok,
       %URI{
         scheme: parsed_did.scheme,
         host: parsed_did.host,
         port: parsed_did.port,
         path: parsed_did.path
       }}
    else
      {:error, "not a did:web identifier"}
    end
  end
end
