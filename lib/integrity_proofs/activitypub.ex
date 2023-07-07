defmodule IntegrityProofs.ActivityPub do
  @moduledoc """
  Functions to create ActivityPub identity proof documents.
  """

  @did_proof_context [
    "https://www.w3.org/ns/activitystreams",
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/data-integrity/v1",
    %{
      "fep" => "https://w3id.org/fep#",
      "VerifiableIdentityStatement" => "fep:VerifiableIdentityStatement",
      "subject" => "fep:subject"
    }
  ]

  defmodule InvalidIntegrityProofError do
    defexception message: nil
  end

  @doc """
  """
  def build_identity_proof!(%{"id" => actor_id} = person, options) do
    subject = Keyword.fetch!(options, :verification_method)

    if !IntegrityProofs.did_uri?(URI.parse(subject)) do
      raise IntegrityProofs.InvalidVerificationMethodURLError, url: subject
    end

    attachment = %{
      "type" => "VerifiableIdentityStatement",
      "subject" => subject,
      "alsoKnownAs" => actor_id
    }

    options = Keyword.put(options, :context, @did_proof_context)
    proof_document = IntegrityProofs.build_assertion_proof!(attachment, options)

    Map.merge(
      person,
      %{
        "@context" => @did_proof_context,
        "attachment" => [proof_document]
      }
    )
  end

  @doc """


  1. The value of the `verificationMethod` property of the data integrity proof
  MUST match the value of `subject` property of the identity proof,
  2. The value of the `alsoKnownAs` property of the identity proof MUST match
  the actor ID.
  3. The proof MUST be verified.
  """
  def verify_identity_proof!(%{"id" => actor_id} = person, options \\ []) do
    %{"subject" => subject, "alsoKnownAs" => aka, "proof" => proof} =
      statement = find_proof!(person)

    if Map.get(proof, "verificationMethod") != subject do
      raise InvalidIntegrityProofError, message: "subject does not match proof.verficationMethod"
    end

    if aka != actor_id do
      raise InvalidIntegrityProofError, message: "alsoKnownAs does not match actor ID"
    end

    options = Keyword.put(options, :context, @did_proof_context)
    IntegrityProofs.verify_proof_document!(statement, options)
  end

  defp find_proof!(person) do
    Map.get(person, "attachment", [])
    |> Enum.find(fn att -> Map.get(att, "type") == "VerifiableIdentityStatement" end)
    |> case do
      %{"subject" => _subject, "alsoKnownAs" => _aka, "proof" => proof} = att
      when is_map(proof) ->
        att

      _ ->
        raise InvalidIntegrityProofError,
          message: "no VerifiableIdentityStatement with proof in 'attachment'"
    end
  end
end
