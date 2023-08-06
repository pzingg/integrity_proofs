defmodule DidServerWeb.UserRegistrationController do
  use DidServerWeb, :controller

  alias DidServer.Accounts
  alias DidServer.Accounts.Account
  alias DidServerWeb.UserAuth

  def new(conn, _params) do
    changeset = Accounts.change_account_registration(%Account{})
    render(conn, :new, changeset: changeset)
  end

  def create(conn, %{"user" => user_params}) do
    case Accounts.register_account(user_params) do
      {:ok, user} ->
        {:ok, _} =
          Accounts.deliver_account_confirmation_instructions(
            user,
            &url(~p"/users/confirm/#{&1}")
          )

        conn
        |> put_flash(:info, "Account created successfully.")
        |> UserAuth.log_in_user(user)

      {:error, %Ecto.Changeset{} = changeset} ->
        render(conn, :new, changeset: changeset)
    end
  end
end
