defmodule DidServerWeb.WebAuthnCredentialController do
  use DidServerWeb, :controller

  require Logger

  alias DidServer.Identities
  alias DidServerWeb.UserAuth

  def new(conn, _params) do
    # redirect_if_user_is_authenticated
    login_with_resident_key(conn)
  end

  def create(conn, %{
        "webauthn" =>
          %{
            "clientDataJSON" => client_data_json,
            "authenticatorData" => authenticator_data_b64,
            "sig" => sig_b64,
            "rawID" => credential_id,
            "type" => "public-key",
            "userHandle" => maybe_user_handle_b64
          } = webauthn_params
      }) do
    maybe_user_handle = if maybe_user_handle_b64 <> "", do: Base.decode64!(maybe_user_handle_b64)
    user = Identities.get_user_key(maybe_user_handle)

    if is_nil(user) do
      authentication_failed(conn, "No user found for handle")
    else
      authenticator_data_raw = Base.decode64!(authenticator_data_b64)
      sig_raw = Base.decode64!(sig_b64)
      challenge = get_session(conn, :authentication_challenge)
      {credentials, handle_mapping} = Identities.get_wax_params(maybe_user_handle)
      aaguid_mapping = get_session(conn, :aaguid_mapping) || handle_mapping

      with {:ok, _} <-
             Wax.authenticate(
               credential_id,
               authenticator_data_raw,
               sig_raw,
               client_data_json,
               challenge,
               credentials
             ),
           :ok <- check_authenticator_status(credential_id, aaguid_mapping, challenge) do
        Logger.debug("Wax: successful authentication for challenge #{inspect(challenge)}")

        conn
        |> put_flash(:info, "Welcome back!")
        |> UserAuth.log_in_user(user, webauthn_params)
      else
        {:error, e} ->
          authentication_failed(conn, Exception.message(e))
      end
    end
  end

  defp authentication_failed(conn, message) do
    conn
    |> put_flash(:error, "Authentication failed: #{message}")
    |> redirect(to: ~p"/wauth/log_in")
  end

  defp login_with_resident_key(conn) do
    challenge = Wax.new_authentication_challenge()

    conn
    |> put_session(:authentication_challenge, challenge)
    |> render(:new,
      login: nil,
      with_webauthn: true,
      challenge: Base.encode64(challenge.bytes),
      rp_id: challenge.rp_id,
      cred_ids: []
    )
  end

  defp login_with_handle(conn, %{user: user, credentials: credentials} = _user_key) do
    handle = DidServer.Accounts.Account.domain_handle(user)

    case credentials do
      [] ->
        render(conn, :new, login: handle, with_webauthn: false)

      _ ->
        {allow_credentials, aaguid_mapping} = Identities.to_wax_params(credentials)
        challenge = Wax.new_authentication_challenge(allow_credentials: allow_credentials)

        Logger.debug("Wax: generated authentication challenge #{inspect(challenge)}")

        conn
        |> put_session(:authentication_challenge, challenge)
        |> put_session(:aaguid_mapping, aaguid_mapping)
        |> render(:new,
          login: handle,
          with_webauthn: true,
          challenge: Base.encode64(challenge.bytes),
          rp_id: challenge.rp_id,
          cred_ids: Enum.map(credentials, fn %{raw_id: cred_id} -> cred_id end)
        )
    end
  end

  defp check_authenticator_status(credential_id, aaguid_mapping, challenge) do
    case aaguid_mapping[credential_id] do
      nil ->
        :ok

      aaguid ->
        case Wax.Metadata.get_by_aaguid(aaguid, challenge) do
          {:ok, _} ->
            :ok

          {:error, _} = error ->
            error
        end
    end
  end
end
