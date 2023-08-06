defmodule DidServer.AccountsTest do
  use DidServer.DataCase

  alias DidServer.Accounts

  import DidServer.AccountsFixtures
  alias DidServer.Accounts.{Account, User, UserToken}
  alias CryptoUtils.Keys.Keypair

  @signer DidServer.LogFixtures.server_signing_key() |> Keypair.to_json()
  @non_existing_uuid "e867fb00-774e-44df-a07b-c1bf04a4d51f"

  describe "get_account_by_email/1" do
    test "does not return the account if the email does not exist" do
      refute Accounts.get_account_by_email("unknown@example.com")
    end

    test "returns the account if the email exists" do
      %{id: id, email: email} = account_fixture()
      assert %Account{id: ^id} = Accounts.get_account_by_email(email)
    end
  end

  describe "get_account_by_email_and_password/2" do
    test "does not return the account if the email does not exist" do
      refute Accounts.get_account_by_email_and_password("unknown@example.com", "hello world!")
    end

    test "does not return the account if the password is not valid" do
      account = account_fixture()
      refute Accounts.get_account_by_email_and_password(account.email, "invalid")
    end

    test "returns the account if the email and password are valid" do
      %{id: id, email: email} = account_fixture()

      assert %Account{id: ^id} =
               Accounts.get_account_by_email_and_password(email, valid_account_password())
    end
  end

  describe "get_account!/1" do
    test "raises if id is invalid" do
      assert_raise Ecto.NoResultsError, fn ->
        Accounts.get_account!(@non_existing_uuid)
      end
    end

    test "returns the account with the given id" do
      %{id: id} = account = account_fixture()
      assert %Account{id: ^id} = Accounts.get_account!(account.id)
    end
  end

  describe "register_account/1" do
    test "requires email and username to be set" do
      assert {:error, changeset} = Accounts.register_account(%{signer: @signer})

      assert %{
               email: ["can't be blank"],
               username: ["can't be blank"],
               domain: ["can't be blank"]
               # password: ["can't be blank"],
             } = errors_on(changeset)
    end

    test "validates email and password when given" do
      {:error, changeset} =
        Accounts.register_account(%{
          email: "not valid",
          username: "a",
          domain: "no",
          signer: @signer
          # password: "not valid"
        })

      assert %{
               email: ["must have the @ sign and no spaces"],
               domain: ["should be at least 3 character(s)"]
               # password: ["should be at least 7 character(s)"]
             } = errors_on(changeset)
    end

    test "validates maximum values for email and password for security" do
      too_long = String.duplicate("db", 100)
      {:error, changeset} = Accounts.register_account(%{email: too_long, password: too_long})
      assert "should be at most 160 character(s)" in errors_on(changeset).email
      # assert "should be at most 72 character(s)" in errors_on(changeset).password
    end

    test "validates email uniqueness" do
      %{email: email} = account_fixture()
      {:error, changeset} = Accounts.register_account(%{email: email})
      assert "has already been taken" in errors_on(changeset).email

      # Now try with the upper cased email too, to check that email case is ignored.
      {:error, changeset} = Accounts.register_account(%{email: String.upcase(email)})
      assert "has already been taken" in errors_on(changeset).email
    end

    test "registers users with a hashed password" do
      email = unique_account_email()
      {:ok, account} = Accounts.register_account(valid_account_attributes(email: email))
      assert account.email == email
      assert is_nil(account.confirmed_at)
      # assert is_binary(account.hashed_password)
      # assert is_nil(account.password)
    end
  end

  describe "change_account_registration/2" do
    test "returns a changeset" do
      assert %Ecto.Changeset{} = changeset = Accounts.change_account_registration(%Account{})

      assert MapSet.new(changeset.required) ==
               MapSet.new([:email, :username, :domain, :signer])
    end

    test "allows fields to be set" do
      email = unique_account_email()
      username = unique_account_username()
      display_name = "Joe #{String.capitalize(username)}"
      description = "Hi, I'm #{display_name}"

      changeset =
        Accounts.change_account_registration(
          %Account{},
          valid_account_attributes(
            email: email,
            display_name: display_name,
            description: description,
            username: username,
            domain: "example.com"
          )
        )

      assert changeset.valid?
      assert get_change(changeset, :email) == email
      assert get_change(changeset, :username) == username
      assert get_change(changeset, :domain) == "example.com"
      # assert get_change(changeset, :password) == password
      # assert is_nil(get_change(changeset, :hashed_password))
    end
  end

  describe "change_account_email/2" do
    test "returns a account changeset" do
      assert %Ecto.Changeset{} = changeset = Accounts.change_account_email(%Account{})
      assert changeset.required == [:email]
    end
  end

  describe "apply_account_email/3" do
    setup do
      %{account: account_fixture()}
    end

    test "requires email to change", %{account: account} do
      {:error, changeset} = Accounts.apply_account_email(account, valid_account_password(), %{})
      assert %{email: ["did not change"]} = errors_on(changeset)
    end

    test "validates email", %{account: account} do
      {:error, changeset} =
        Accounts.apply_account_email(account, valid_account_password(), %{email: "not valid"})

      assert %{email: ["must have the @ sign and no spaces"]} = errors_on(changeset)
    end

    test "validates maximum value for email for security", %{account: account} do
      too_long = String.duplicate("db", 100)

      {:error, changeset} =
        Accounts.apply_account_email(account, valid_account_password(), %{email: too_long})

      assert "should be at most 160 character(s)" in errors_on(changeset).email
    end

    test "validates email uniqueness", %{account: account} do
      %{email: email} = account_fixture()
      password = valid_account_password()

      {:error, changeset} = Accounts.apply_account_email(account, password, %{email: email})

      assert "has already been taken" in errors_on(changeset).email
    end

    test "validates current password", %{account: account} do
      {:error, changeset} =
        Accounts.apply_account_email(account, "invalid", %{email: unique_account_email()})

      assert %{current_password: ["is not valid"]} = errors_on(changeset)
    end

    test "applies the email without persisting it", %{account: account} do
      email = unique_account_email()

      {:ok, account} =
        Accounts.apply_account_email(account, valid_account_password(), %{email: email})

      assert account.email == email
      assert Accounts.get_account!(account.id).email != email
    end
  end

  describe "deliver_user_update_email_instructions/3" do
    setup do
      %{user: user_fixture()}
    end

    test "sends token through notification", %{user: user} do
      token =
        extract_user_token(fn url ->
          Accounts.deliver_user_update_email_instructions(user, "current@example.com", url)
        end)

      {:ok, token} = Base.url_decode64(token, padding: false)
      assert user_token = Repo.get_by(UserToken, token: :crypto.hash(:sha256, token))
      assert user_token.user_id == user.id
      assert user_token.sent_to == user.account.email
      assert user_token.context == "change:current@example.com"
    end
  end

  describe "update_user_email/2" do
    setup do
      %User{account: %{email: original_email} = account} = user = user_fixture()

      email = unique_account_email()
      changed_account = %Account{account | email: email}

      token =
        extract_user_token(fn url ->
          Accounts.deliver_user_update_email_instructions(
            %User{user | account: changed_account},
            original_email,
            url
          )
        end)

      %{user: user, token: token, email: email}
    end

    test "updates the email with a valid token", %{user: user, token: token, email: email} do
      assert Accounts.update_user_email(user, token) == :ok
      repo_user = Repo.get!(User, user.id) |> Repo.preload(:account)
      assert repo_user.account.email != user.account.email
      assert repo_user.account.email == email
      assert repo_user.account.confirmed_at
      assert repo_user.account.confirmed_at != user.account.confirmed_at
      refute Repo.get_by(UserToken, user_id: user.id)
    end

    test "does not update email with invalid token", %{user: user} do
      assert Accounts.update_user_email(user, "oops") == :error
      repo_user = Repo.get!(User, user.id) |> Repo.preload(:account)
      assert repo_user.account.email == user.account.email
      assert Repo.get_by(UserToken, user_id: user.id)
    end

    test "does not update email if account email changed", %{
      user: %User{account: account} = user,
      token: token
    } do
      changed_account = %Account{account | email: "current@example.com"}
      assert Accounts.update_user_email(%User{user | account: changed_account}, token) == :error

      repo_user = Repo.get!(User, user.id) |> Repo.preload(:account)
      assert repo_user.account.email == user.account.email
      assert Repo.get_by(UserToken, user_id: user.id)
    end

    test "does not update email if token expired", %{user: user, token: token} do
      {1, nil} = Repo.update_all(UserToken, set: [inserted_at: ~N[2020-01-01 00:00:00]])
      assert Accounts.update_user_email(user, token) == :error

      repo_user = Repo.get!(User, user.id) |> Repo.preload(:account)
      assert repo_user.account.email == user.account.email
      assert Repo.get_by(UserToken, user_id: user.id)
    end
  end

  describe "generate_user_session_token/1" do
    setup do
      %{user: user_fixture()}
    end

    test "generates a token", %{user: user} do
      token = Accounts.generate_user_session_token(user)
      assert user_token = Repo.get_by(UserToken, token: token)
      assert user_token.context == "session"

      # Creating the same token for another account should fail
      assert_raise Ecto.ConstraintError, fn ->
        Repo.insert!(%UserToken{
          token: user_token.token,
          user_id: user_fixture().id,
          context: "session"
        })
      end
    end
  end

  describe "get_user_by_session_token/1" do
    setup do
      user = user_fixture()
      token = Accounts.generate_user_session_token(user)
      %{user: user, token: token}
    end

    test "returns account by token", %{user: user, token: token} do
      assert session_user = Accounts.get_user_by_session_token(token)
      assert session_user.id == user.id
    end

    test "does not return account for invalid token" do
      refute Accounts.get_user_by_session_token("oops")
    end

    test "does not return account for expired token", %{token: token} do
      {1, nil} = Repo.update_all(UserToken, set: [inserted_at: ~N[2020-01-01 00:00:00]])
      refute Accounts.get_user_by_session_token(token)
    end
  end

  describe "delete_user_session_token/1" do
    test "deletes the token" do
      user = user_fixture()
      token = Accounts.generate_user_session_token(user)
      assert Accounts.delete_user_session_token(token) == :ok
      refute Accounts.get_user_by_session_token(token)
    end
  end

  describe "deliver_user_confirmation_instructions/2" do
    setup do
      %{user: user_fixture()}
    end

    test "sends token through notification", %{user: user} do
      token =
        extract_user_token(fn url ->
          Accounts.deliver_user_confirmation_instructions(user, url)
        end)

      {:ok, token} = Base.url_decode64(token, padding: false)
      assert user_token = Repo.get_by(UserToken, token: :crypto.hash(:sha256, token))
      assert user_token.user_id == user.id
      assert user_token.sent_to == user.account.email
      assert user_token.context == "confirm"
    end
  end

  describe "confirm_user/1" do
    setup do
      user = user_fixture()

      token =
        extract_user_token(fn url ->
          Accounts.deliver_user_confirmation_instructions(user, url)
        end)

      %{user: user, token: token}
    end

    test "confirms the email with a valid token", %{user: user, token: token} do
      assert {:ok, confirmed_account} = Accounts.confirm_user(token)
      assert confirmed_account.confirmed_at
      assert confirmed_account.confirmed_at != user.account.confirmed_at
      assert Repo.get!(Account, user.account.id).confirmed_at
      refute Repo.get_by(UserToken, user_id: user.id)
    end

    test "does not confirm with invalid token", %{user: user} do
      assert Accounts.confirm_user("oops") == :error
      refute Repo.get!(Account, user.account.id).confirmed_at
      assert Repo.get_by(UserToken, user_id: user.id)
    end

    test "does not confirm email if token expired", %{user: user, token: token} do
      {1, nil} = Repo.update_all(UserToken, set: [inserted_at: ~N[2020-01-01 00:00:00]])
      assert Accounts.confirm_user(token) == :error
      refute Repo.get!(Account, user.account.id).confirmed_at
      assert Repo.get_by(UserToken, user_id: user.id)
    end
  end

  describe "deliver_user_reset_password_instructions/2" do
    setup do
      %{user: user_fixture()}
    end

    test "sends token through notification", %{user: user} do
      token =
        extract_user_token(fn url ->
          Accounts.deliver_user_reset_password_instructions(user, url)
        end)

      {:ok, token} = Base.url_decode64(token, padding: false)
      assert user_token = Repo.get_by(UserToken, token: :crypto.hash(:sha256, token))
      assert user_token.user_id == user.id
      assert user_token.sent_to == user.account.email
      assert user_token.context == "reset_password"
    end
  end

  describe "get_user_by_reset_password_token/1" do
    setup do
      user = user_fixture()

      token =
        extract_user_token(fn url ->
          Accounts.deliver_user_reset_password_instructions(user, url)
        end)

      %{user: user, token: token}
    end

    test "returns the account with valid token", %{user: %{id: id}, token: token} do
      assert %User{id: ^id} = Accounts.get_user_by_reset_password_token(token)
      assert Repo.get_by(UserToken, user_id: id)
    end

    test "does not return the account with invalid token", %{user: user} do
      refute Accounts.get_user_by_reset_password_token("oops")
      assert Repo.get_by(UserToken, user_id: user.id)
    end

    test "does not return the account if token expired", %{user: user, token: token} do
      {1, nil} = Repo.update_all(UserToken, set: [inserted_at: ~N[2020-01-01 00:00:00]])
      refute Accounts.get_user_by_reset_password_token(token)
      assert Repo.get_by(UserToken, user_id: user.id)
    end
  end
end
