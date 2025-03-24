defmodule Integrity.Credential do
  @moduledoc """
  See https://w3c.github.io/vc-data-model/
  """

  def sign(credential, keystore, resolver, options) do
    with {:ok, valid_credential} <-
           validate(credential),
         {:ok, issuer} <-
           get_issuer(valid_credential),
         {:key, {:ok, {public_key, private_key}}} <-
           {:key, pick_key(keystore, issuer, resolver, options)} do
      case Keyword.get(options, :proof_format, "ldp") do
        "ldp" ->
          verification_method = Keyword.fetch!(options, :verification_method)
          proof_purpose = Keyword.get(options, :proof_purpose, "assertionMethod")
          cryptosuite = Keyword.get(options, :cryptosuite, "eddsa-jcs-2022")
          curve = Keyword.get(options, :curve, "ed25519")

          case cryptosuite do
            "eddsa-jcs-2022" ->
              {:ok,
               Integrity.build_assertion_proof!(valid_credential,
                 type: "DataIntegrityProof",
                 cryptosuite: cryptosuite,
                 created: CryptoUtils.format_datetime(),
                 verification_method: verification_method,
                 proof_purpose: proof_purpose,
                 curve: curve,
                 public_key_bytes: public_key,
                 private_key_bytes: private_key
               )}

            _ ->
              {:error, %{status_code: 400, reason: "Cryptosuite #{cryptosuite} not supported"}}
          end

        "jwt" ->
          {:error, %{status_code: 500, reason: "Proof format jwt not supported"}}

        fmt ->
          {:error, %{status_code: 400, reason: "Proof format #{fmt} not supported"}}
      end
    else
      {:key, {:error, reason}} ->
        {:error, %{status_code: 404, reason: reason}}

      {:error, reason} when is_binary(reason) ->
        {:error, %{status_code: 400, reason: reason}}

      error_map ->
        error_map
    end
  end

  def validate(credential) do
    with :ok <- has_required_keys?(credential),
         :ok <- is_verified_credential?(credential),
         :ok <- has_subject?(credential) do
      maybe_set_issuance_date(credential)
    end
  end

  defp pick_key(keystore, issuer, did_resolver, options) do
    vm = Keyword.get(options, :verification_method)
    match_key(keystore, issuer, did_resolver, vm)
  end

  defp match_key(keystore, _, did_resolver, vm) when is_binary(vm) do
    with {:ok, public_key} <- resolve_key(did_resolver, vm) do
      case keystore.get(:any, public_key) do
        nil -> {:error, "Resolved key not found"}
        private_key -> {:ok, {public_key, private_key}}
      end
    end
  end

  defp match_key(keystore, issuer, _, _) when is_binary(issuer) do
    method = CryptoUtils.Did.get_method!(issuer)

    [:user, :system]
    |> Enum.map(fn user_key ->
      keystore.list(user_key)
      |> Enum.map(fn {public_key, private_key} -> {user_key, public_key, private_key} end)
    end)
    |> List.flatten()
    |> Enum.reduce_while({:error, "No matching key"}, fn {_user_key, public_key, private_key},
                                                         acc ->
      case method.generate(public_key) do
        {:ok, did} ->
          if did == issuer do
            {:halt, {:ok, {public_key, private_key}}}
          else
            {:cont, acc}
          end

        _ ->
          {:cont, acc}
      end
    end)
  end

  defp match_key(keystore, _, _, _), do: keystore.first()

  # Resolve a verificationMethod to a key.
  defp resolve_key(resolver, verification_method, fmt \\ [:jwk]) do
    with {:ok, vm} <- resolve_vm(resolver, verification_method) do
      CryptoUtils.Keys.extract_multikey(vm, fmt)
    end
  end

  # Resolve a verificationMethod.
  defp resolve_vm(resolver, verification_method) do
    case resolver.dereference(verification_method, []) do
      {:error, {res_meta, _, _}} ->
        {:error, res_meta.error}

      {:ok, {_, {:object, object}, _}} ->
        {:ok, object}

      _ ->
        {:error, "Verification method #{verification_method} not found"}
    end
  end

  defp has_required_keys?(credential) do
    if Enum.all?(["issuer"], fn key ->
         Map.has_key?(credential, key)
       end) do
      :ok
    else
      {:error, "Invalid credential"}
    end
  end

  defp is_verified_credential?(credential) do
    types =
      Map.get(credential, "type", [])
      |> List.wrap()

    if "VerifiableCredential" in types do
      :ok
    else
      {:error, "Not a verifiable credential"}
    end
  end

  defp has_subject?(credential) do
    subject = Map.get(credential, "credentialSubject")

    if is_map(subject) && map_size(subject) != 0 do
      :ok
    else
      {:error, "No credential subject"}
    end
  end

  defp maybe_set_issuance_date(%{"issuanceDate" => _} = credential) do
    {:ok, credential}
  end

  defp maybe_set_issuance_date(credential) do
    {:ok,
     Map.put(
       credential,
       "issuanceDate",
       NaiveDateTime.utc_now() |> CryptoUtils.format_datetime()
     )}
  end

  defp get_issuer(credential) do
    case Map.get(credential, "issuer") do
      id when is_binary(id) -> {:ok, id}
      %{"id" => id} -> {:ok, id}
      _ -> {:error, "No issuer"}
    end
  end
end
