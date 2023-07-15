defmodule DidServer do
  @moduledoc """
  Elixir implementation of Bluesky's did:plc method.

  See https://github.com/bluesky-social/did-method-plc
  """

  defmodule PrevMismatchError do
    defexception [:message]
  end
end
