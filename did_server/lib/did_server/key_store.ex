defmodule DidServer.KeyStore do
  @moduledoc """
  A behaviour for storing private keys.
  """

  @type user_key() :: atom() | integer() | binary()
  @type did() :: binary()
  @type public_key() :: did()
  @type private_key() :: binary()
  @type entry() :: {public_key(), private_key()}

  @callback size(user_key()) :: integer()
  @callback list(user_key()) :: [entry()]
  @callback first(user_key()) :: entry() | nil
  @callback get(user_key(), public_key()) :: private_key() | nil
  @callback put(user_key(), public_key(), private_key()) :: :ok
  @callback delete(user_key(), public_key()) :: :ok
end
