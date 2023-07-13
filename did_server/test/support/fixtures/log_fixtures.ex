defmodule DidServer.LogFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `DidServer.Log` context.
  """

  @doc """
  Generate a did.
  """
  def did_fixture(attrs \\ %{did: "did:plc:y54rrfl37i5wqztksze4bddl"}) do
    {:ok, did} =
      attrs
      |> Enum.into(%{})
      |> DidServer.Log.create_did()

    did
  end
end
