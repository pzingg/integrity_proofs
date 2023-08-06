defmodule DidServerWeb.UserSettingsController do
  use DidServerWeb, :controller

  alias DidServer.{Accounts, Identities, Log}
  alias DidServerWeb.UserAuth

  plug(:assign_email_and_password_changesets)

  def edit(conn, _params) do
    render(conn, :edit)
  end

  def update(conn, %{"action" => "update_email"} = params) do
    %{"current_password" => password, "user" => user_params} = params

    # require_authenticated_user
    %{user: user, key: key} = conn.assigns.current_user

    case Accounts.apply_user_email(user, password, user_params) do
      {:ok, applied_user} ->
        Accounts.deliver_user_update_email_instructions(
          applied_user,
          user.email,
          &url(~p"/users/settings/confirm_email/#{&1}")
        )

        conn
        |> put_flash(
          :info,
          "A link to confirm your email change has been sent to the new address."
        )
        |> redirect(to: ~p"/users/settings")

      {:error, changeset} ->
        render(conn, :edit, email_changeset: changeset)
    end
  end

  def update(conn, %{"action" => "update_username"} = params) do
    %{"current_password" => password, "user" => user_params} = params

    # require_authenticated_user
    %{user: user, key: key} = conn.assigns.current_user

    case Accounts.update_user_username(user, password, user_params) do
      {:ok, user} ->
        conn
        |> put_flash(:info, "Username updated successfully.")
        |> put_session(:user_return_to, ~p"/users/settings")
        |> UserAuth.log_in_user(user)

      {:error, changeset} ->
        render(conn, :edit, username_changeset: changeset)
    end
  end

  def update(conn, %{"action" => "update_password"} = params) do
    %{"current_password" => password, "key" => %{"current_user_id" => user_id} = key_params} =
      params

    # require_authenticated_user
    %{user: user, key: key} = conn.assigns.current_user

    if is_nil(key) || user.id != user_id do
      conn
      |> put_status(500)
      |> put_view(ErrorJSON)
      |> render("500.json", "Internal Server Error: user id mismatch")
    else
      case Identities.update_did_password(key, password, key_params) do
        {:ok, _key} ->
          conn
          |> put_flash(:info, "Password updated successfully.")
          |> put_session(:user_return_to, ~p"/users/settings")
          |> UserAuth.log_in_user(user)

        {:error, changeset} ->
          render(conn, :edit, password_changeset: changeset)
      end
    end
  end

  def confirm_email(conn, %{"token" => token}) do
    # require_authenticated_user
    %{user: user, key: key} = conn.assigns.current_user

    case Accounts.update_user_email(user, token) do
      :ok ->
        conn
        |> put_flash(:info, "Email changed successfully.")
        |> redirect(to: ~p"/users/settings")

      :error ->
        conn
        |> put_flash(:error, "Email change link is invalid or it has expired.")
        |> redirect(to: ~p"/users/settings")
    end
  end

  defp assign_email_and_password_changesets(conn, _opts) do
    # require_authenticated_user
    %{user: user, key: key} = conn.assigns.current_user

    conn
    |> assign(:email_changeset, Accounts.change_user_email(user))
    |> assign(:username_changeset, Accounts.change_user_username(user))
    |> assign(:password_changeset, Identities.change_did_password(key, user.id))
    |> assign(:password_did, key.did)
  end
end
