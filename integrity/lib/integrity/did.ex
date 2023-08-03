defmodule Integrity.Did do
  @moduledoc """
  Functions to create and resolve DID documents.

  Section references refer to [The did:key Method v0.7](https://w3c-ccg.github.io/did-method-key/)

  See also the [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/)
  """

  alias Integrity.DidResolutionError

  @doc """
  For "did:web" and other HTTP-reliant methods, use a resolver to
  fetch and decode a DID document.
  """
  def resolve_did_web!(identifier, options) when is_binary(identifier) do
    CryptoUtils.Did.parse_did!(identifier, options)
    |> resolve_did_web!(options)
  end

  def resolve_did_web!(%{method: :web, did_string: identifier} = parsed_did, options) do
    fetcher = Keyword.fetch!(options, :web_resolver)

    url =
      %URI{
        scheme: parsed_did.scheme,
        host: parsed_did.host,
        port: parsed_did.port,
        path: parsed_did.path
      }
      |> URI.to_string()

    with {:ok, doc_json} <- fetcher.fetch(url, []),
         {:ok, document} <- Jason.decode(doc_json) do
      document
    else
      {:error, reason} -> raise DidResolutionError, did: identifier, reason: reason
    end
  end

  def resolve_did_web!(%{method: method, did_string: identifier}, _) do
    raise DidResolutionError, did: identifier, reason: "invalid DID method #{method}"
  end
end
