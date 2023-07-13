defmodule IntegrityProofs.ActivityPub do
  @moduledoc """
  Functions to create ActivityPub identity proof documents.

  See [Fediverse Enhancement Proposal FEP-c390: Identity Proofs](https://codeberg.org/silverpill/feps/src/branch/main/c390/fep-c390.md)
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

  defmodule MissingIntegrityProofError do
    defexception []

    @impl true
    def message(_) do
      "no VerfiableIdentityStatement in attachment"
    end
  end

  defmodule InvalidIntegrityProofError do
    defexception [:message]

    @impl true
    def exception(reason) do
      %__MODULE__{message: reason}
    end
  end

  @doc """
  Builds an assertion proof from a `VerifiableIdentityStatement`
  document linking a verification method (DID) to an ActivityPub Actor ID,
  as described in FEP-c390.

  The proof is prepended to the (possibly empty) `attachment` property
  of the Actor document.

  Returns the Actor document with the attached proof.
  """
  def build_identity_proof!(%{"id" => actor_id} = person, options) do
    subject = Keyword.fetch!(options, :verification_method)

    if !IntegrityProofs.did_uri?(URI.parse(subject)) do
      raise IntegrityProofs.InvalidVerificationMethodURLError, subject
    end

    attachment = %{
      "type" => "VerifiableIdentityStatement",
      "subject" => subject,
      "alsoKnownAs" => actor_id
    }

    options = Keyword.put(options, :context, @did_proof_context)
    proof_document = IntegrityProofs.build_assertion_proof!(attachment, options)

    {attachments, person} = Map.pop(person, "attachment", [])

    Map.merge(
      person,
      %{
        "@context" => @did_proof_context,
        "attachment" => [proof_document | attachments]
      }
    )
  end

  @doc """
  Verifies the first proof atttached to an Actor document, as described in
  FEP-c390.

  1. The value of the `verificationMethod` property of the data integrity proof
  MUST match the value of `subject` property of the identity proof,
  2. The value of the `alsoKnownAs` property of the identity proof MUST match
  the actor ID.
  3. The proof MUST be verified.

  Returns `true` if the proof can be verified.

  Raises an error if there is no correctly formatted `VerifiableIdentityStatement`
  in the Actor's `attachment` property, or if the conditions above are not met.
  """
  def verify_identity_proof!(%{"id" => actor_id} = person, options \\ []) do
    %{"subject" => subject, "alsoKnownAs" => aka, "proof" => proof} =
      statement = find_proof!(person)

    if Map.get(proof, "verificationMethod") != subject do
      raise InvalidIntegrityProofError, "subject does not match proof.verficationMethod"
    end

    if aka != actor_id do
      raise InvalidIntegrityProofError, "alsoKnownAs does not match actor ID"
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
        raise MissingIntegrityProofError
    end
  end
end
