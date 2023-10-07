defmodule CryptoUtils.Did.Method do
  @moduledoc """
  A behaviour for Did methods.
  """

  @callback name() :: String.t()
  @callback to_resolver() :: module()

  @doc """
  Find the handler module for a Did method
  """
  def lookup(:key), do: CryptoUtils.Did.Methods.DidKey
  def lookup(:web), do: CryptoUtils.Did.Methods.DidWeb
  def lookup(:plc), do: CryptoUtils.Did.Methods.DidPlc

  def lookup(key) do
    raise ArgumentError, "No implmentation for did:#{key} method"
  end
end
