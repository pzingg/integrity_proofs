defmodule CryptoUtils.Did.Methods.DidPlc do
  @moduledoc """
  Handler for the did:key method.
  """

  @behaviour CryptoUtils.Did.Method
  @behaviour CryptoUtils.Did.Resolver

  alias CryptoUtils.Did.{ResolutionInputMetadata, DocumentMetadata, ResolutionMetadata}

  @impl CryptoUtils.Did.Method
  def name() do
    "plc"
  end

  @impl CryptoUtils.Did.Method
  def to_resolver() do
    __MODULE__
  end

  @impl CryptoUtils.Did.Resolver
  def resolve(_module, did, _input_metadata) do
    error_result("TODO")
  end

  @impl CryptoUtils.Did.Resolver
  def resolve_representation(_module, _did, _input_metadata) do
    error_result("TODO")
  end

  defp error_result(error) do
    {:error, {%ResolutionMetadata{error: error}, nil, nil}}
  end
end
