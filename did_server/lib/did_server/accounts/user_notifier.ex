defmodule DidServer.Accounts.UserNotifier do
  @moduledoc """
  A null notifier.
  """

  # import Swoosh.Email
  # alias DidServer.Mailer

  # Delivers the email using the application mailer.
  defp deliver(recipient, subject, body) do
    name = DidServer.Application.name()
    from_address = DidServer.Application.email_from()

    _old_code = """
    email =
      new()
      |> to(recipient)
      |> from({name, from_address})
      |> subject(subject)
      |> text_body(body)

    with {:ok, _metadata} <- Mailer.deliver(email) do
      {:ok, email}
    end
    """

    # IO.puts("To: #{recipient}\n\n#{body}")

    {:ok, %{to: recipient, from: "#{name} <#{from_address}>", subject: subject, text_body: body}}
  end

  @doc """
  Deliver instructions to confirm account.
  """
  def deliver_confirmation_instructions(account, url) do
    deliver(account.email, "Confirmation instructions", """

    ==============================

    Hi #{account.email},

    You can confirm your account by visiting the URL below:

    #{url}

    If you didn't create an account with us, please ignore this.

    ==============================
    """)
  end

  @doc """
  Deliver instructions to reset an account password.
  """
  def deliver_reset_password_instructions(account, url) do
    deliver(account.email, "Reset password instructions", """

    ==============================

    Hi #{account.email},

    You can reset your password by visiting the URL below:

    #{url}

    If you didn't request this change, please ignore this.

    ==============================
    """)
  end

  @doc """
  Deliver instructions to update an account email.
  """
  def deliver_update_email_instructions(account, url) do
    deliver(account.email, "Update email instructions", """

    ==============================

    Hi #{account.email},

    You can change your email by visiting the URL below:

    #{url}

    If you didn't request this change, please ignore this.

    ==============================
    """)
  end
end
