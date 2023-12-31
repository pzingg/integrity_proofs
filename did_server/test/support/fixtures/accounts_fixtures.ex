defmodule DidServer.AccountsFixtures do
  @moduledoc """
  This module defines test helpers for creating
  entities via the `DidServer.Accounts` context.
  """

  alias CryptoUtils.Keys.Keypair

  @example_domain "example.com"

  def unique_account_email, do: "#{unique_account_username()}@#{@example_domain}"
  def unique_account_username, do: "user#{System.unique_integer()}"
  defdelegate valid_account_password, to: DidServer.LogFixtures, as: :valid_did_password

  def valid_account_attributes(attrs \\ %{}) do
    username = unique_account_username()
    display_name = "Joe #{String.capitalize(username)}"
    description = "Hi, I'm #{display_name}"
    domain = @example_domain
    email = "#{username}@#{domain}"
    password = valid_account_password()
    keypair = DidServer.LogFixtures.server_signing_key()

    Enum.into(attrs, %{
      display_name: display_name,
      description: description,
      email: email,
      username: username,
      domain: domain,
      password: password,
      signer: Keypair.to_json(keypair),
      signing_key: Keypair.did(keypair),
      recovery_key: Keypair.did(keypair)
    })
  end

  def account_fixture(attrs \\ %{}) do
    attrs
    |> valid_account_attributes()
    |> DidServer.Accounts.register_account()
    |> case do
      {:ok, account} ->
        account

      {:error, changeset} ->
        raise RuntimeError, "account fixture failed #{inspect(changeset.errors)}"
    end
  end

  def user_fixture(attrs \\ %{}) do
    account = account_fixture(attrs) |> DidServer.Repo.preload(:users)
    hd(account.users) |> DidServer.Repo.preload(:account)
  end

  def extract_user_token(fun) do
    {:ok, captured_email} = fun.(&"[TOKEN]#{&1}[TOKEN]")
    [_, token | _] = String.split(captured_email.text_body, "[TOKEN]")
    token
  end
end
