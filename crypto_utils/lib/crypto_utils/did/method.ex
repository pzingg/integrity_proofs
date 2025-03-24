defmodule CryptoUtils.Did.Method do
  @moduledoc """
  A behaviour for Did methods.
  """

  @callback name() :: String.t()
  @callback generate(public_key :: term()) :: String.t() | nil
  @callback to_resolver() :: module()
  @callback validate(CryptoUtils.Did.basic_parts(), Keyword.t()) :: {:ok, map()} | :error

  @optional_callbacks generate: 1

  @doc """
  Find the handler module for a Did method
  """
  def lookup!(:key), do: CryptoUtils.Did.Methods.DidKey
  def lookup!(:web), do: CryptoUtils.Did.Methods.DidWeb
  def lookup!(:plc), do: CryptoUtils.Did.Methods.DidPlc

  def lookup!(method) do
    raise ArgumentError, "No implmentation for did:#{method} method"
  end
end
