defmodule DidServer.AccountsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `DidServer.Accounts` context.
  """

  alias DidServer.Accounts.User

  @example_domain "example.com"

  def unique_user_email, do: "#{unique_user_username()}@#{@example_domain}"
  def unique_user_username, do: "user#{System.unique_integer()}"
  defdelegate valid_user_password, to: DidServer.LogFixtures, as: :valid_did_password

  def valid_user_attributes(attrs \\ %{}) do
    username = unique_user_username()
    domain = @example_domain
    email = "#{username}@#{domain}"

    Enum.into(attrs, %{
      email: email,
      username: username,
      domain: domain
    })
  end

  def user_fixture(attrs \\ %{}) do
    {:ok, user} =
      attrs
      |> valid_user_attributes()
      |> DidServer.Accounts.register_user()

    did = DidServer.LogFixtures.did_fixture(%{handle: User.domain_handle(user)})
    _link = DidServer.Log.add_also_known_as(did, user)

    user
  end

  def extract_user_token(fun) do
    {:ok, captured_email} = fun.(&"[TOKEN]#{&1}[TOKEN]")
    [_, token | _] = String.split(captured_email.text_body, "[TOKEN]")
    token
  end
end
