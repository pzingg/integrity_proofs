defmodule DidServer do
  @moduledoc """
  Elixir implementation of Bluesky's did:plc method.

  See https://github.com/bluesky-social/did-method-plc
  """

  defmodule PrevMismatchError do
    defexception [:message]
  end

  defmodule UpdateOperationError do
    defexception [:message]

    @impl true
    def exception(reason) do
      %__MODULE__{message: "update operation error: #{reason}"}
    end
  end
end
