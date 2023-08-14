defmodule DidServerWeb.WebAuthnKeyController do
  use DidServerWeb, :controller

  require Logger

  # Notes from https://developers.google.com/codelabs/passkey-form-autofill
  #
  # Caution: On a device that doesn't support a biometric sensor, such
  # as an iMac, setting the authenticatorSelection.userVerification
  # parameter to a "preferred" value results in no user verification
  # requested to the user, which immediately returns a credential that
  # contains the UV (user verification) flag with a false value.
  # This is an expected behavior for this codelab because the server
  # doesn't require the UV flag as you can see in the libs/auth.mjs file.
  # If you want to always require a user verification, set the
  # authenticatorSelection.userVerification property to a "required"
  # value and replace the line in the libs/auth.mjs file with a
  # requireUserVerification property set to a true value.
  #
  # Caution: Some browsers don't require any parameters on the
  # authenticatorSelection dictionary to create a passkey, but others
  # might. We recommend that you specify these parameters explicitly.

  def new(conn, params) do
    # require_authenticated_user
    %{id: user_id, account: account} = conn.assigns.current_user
    handle = DidServer.Accounts.Account.domain_handle(account)
    user_id = Base.encode64(user_id)

    opts =
      if Map.get(params, "direct", "false") == "true" do
        [
          attestation: "direct",
          trusted_attestation_types: [:basic, :uncertain, :attca, :anonca],
          # Disable to make it work with Chrome Virtual Authenticator
          # Do not disable it if you don't know what you're doing!!!!
          verify_trust_root: false
        ]
      else
        []
      end

    challenge = Wax.new_registration_challenge(opts)

    Logger.debug("Wax: generated attestation challenge #{inspect(challenge)}")

    conn
    |> put_session(:wa_challenge, challenge)
    |> put_session(:wa_user_id, user_id)
    |> render(:new,
      login: handle,
      challenge: Base.encode64(challenge.bytes),
      rp_id: challenge.rp_id,
      rp_name: DidServer.Application.name(),
      user: handle,
      user_id: user_id,
      attestation: challenge.attestation,
      cred_algs: supported_cred_algs()
    )
  end

  def create(conn, %{
        "key" => %{
          "attestationObject" => attestation_object_b64,
          "clientDataJSON" => client_data_json,
          "rawID" => raw_id_b64,
          "type" => "public-key"
        }
      }) do
    challenge = get_session(conn, :wa_challenge)
    user_id_b64 = get_session(conn, :wa_user_id)

    # user_id is the UUID for the Key record
    user_id =
      if is_nil(user_id_b64) do
        nil
      else
        Base.decode64!(user_id_b64)
      end

    attestation_object = Base.decode64!(attestation_object_b64)

    case Wax.register(attestation_object, client_data_json, challenge) do
      {:ok, {authenticator_data, result}} ->
        Logger.debug(
          "Wax: attestation object validated with result #{inspect(result)} " <>
            " and authenticator data #{inspect(authenticator_data)}"
        )

        cose_key = authenticator_data.attested_credential_data.credential_public_key
        maybe_aaguid = Wax.AuthenticatorData.get_aaguid(authenticator_data)
        IO.inspect(cose_key, label: :cose_key)

        case DidServer.Identities.register_credential(user_id, raw_id_b64, cose_key, maybe_aaguid) do
          {:ok, _credential} ->
            conn
            |> put_flash(:info, "Key registered")
            |> redirect(to: ~p"/users/settings")

          {:error, changeset} ->
            Logger.error("Key registration failed (#{inspect(DidServer.errors_on(changeset))})")

            registration_failed(conn, "Could not store credential")
        end

      {:error, e} = error ->
        Logger.debug("Wax: attestation object validation failed with error #{inspect(error)}")

        registration_failed(conn, Exception.message(e))
    end
  end

  defp registration_failed(conn, message) do
    conn
    |> put_flash(:error, "Key registration failed: #{message}")
    |> redirect(to: ~p"/wauth/register")
  end

  # Note: if you add :ed25519 to the list,
  # Chrome will not pop-up the passkey dialog. Apparently
  # only :p256 curves are supported for cross-platform keys.
  #
  # Google's tutorial specifies support for ECDSA with P-256 (:p256) and
  # RSA PKCS#1 (curve :rs256, COSE alg -257), and says that supporting
  # these "gives complete coverage".
  defp supported_cred_algs do
    [:p256]
    |> Enum.map(fn curve ->
      %{alg: alg} = CryptoUtils.Curves.cose(curve)
      alg
    end)
  end
end
