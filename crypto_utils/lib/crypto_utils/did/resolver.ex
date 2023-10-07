defmodule CryptoUtils.Did.Resolver do
  @moduledoc """
  A behaviour for resolving a DID.
  """

  alias CryptoUtils.Did.{ResolutionInputMetadata, DocumentMetadata, ResolutionMetadata}

  @callback resolve(
              did_module :: module(),
              did :: String.t(),
              input_metadata :: ResolutionInputMetadata.t()
            ) ::
              {:ok, {meta :: ResolutionMetadata.t(), map(), DocumentMetadata.t()}}
              | {:error, {meta :: ResolutionMetadata.t(), nil, nil}}

  @callback resolve_representation(
              did_module :: module(),
              did :: String.t(),
              input_metadata :: ResolutionInputMetadata.t()
            ) ::
              {:ok, {meta :: ResolutionMetadata.t(), map(), DocumentMetadata.t()}}
              | {:error, {meta :: ResolutionMetadata.t(), nil, nil}}
end
