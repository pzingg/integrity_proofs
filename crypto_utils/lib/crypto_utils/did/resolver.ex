defmodule CryptoUtils.Did.Resolver do
  @moduledoc """
  A behaviour for resolving a DID.
  """

  alias CryptoUtils.Did

  @doc """
  [Resolve a DID](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm)

  i.e. the `resolve` function from [DID Core](https://www.w3.org/TR/did-core/#did-resolution)
  and [DID Resolution](https://w3c-ccg.github.io/did-resolution/#resolving).
  """
  @callback resolve(
              did :: String.t(),
              input_metadata :: Did.resolution_input_metadata()
            ) ::
              {:ok, {Did.resolution_metadata(), doc :: map(), Did.document_metadata()}}
              | {:error, {Did.resolution_metadata(), nil, nil}}

  @doc """
  [Resolve a DID](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm) in a given representation

  i.e. the `resolveRepresentation` function from [DID Core](https://www.w3.org/TR/did-core/#did-resolution)
  and [DID Resolution](https://w3c-ccg.github.io/did-resolution/#resolving).
  """
  @callback resolve_representation(
              did :: String.t(),
              input_metadata :: Did.resolution_input_metadata()
            ) ::
              {:ok, {Did.resolution_metadata(), doc_data :: term(), Did.document_metadata()}}
              | {:error, {Did.resolution_metadata(), nil, nil}}

  @doc """
  Dereference a DID URL.

  DID methods implement this function to support [dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing)
  DID URLs with paths and query strings.
  """
  @callback dereference(
              primary_did_url :: String.t(),
              did_url_dereferencing_input_metadata :: Did.dereferencing_input_metadata()
            ) ::
              {:ok, {Did.dereferencing_metadata(), content :: term(), Did.content_metadata()}}
              | :error

  @optional_callbacks resolve_representation: 2, dereference: 2
end
