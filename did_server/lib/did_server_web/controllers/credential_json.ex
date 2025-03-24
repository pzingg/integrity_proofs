defmodule DidServerWeb.CredentialJSON do
  def example_credential(%{issuer: issuer, subject_id: subject_id}) do
    new_id = "https://localhost:4000/credentials/#{UUID.uuid4()}"

    %{
      "credential" => %{
        "@context" => "https://www.w3.org/2018/credentials/v1",
        "id" => new_id,
        "type" => ["VerifiableCredential"],
        "issuer" => issuer,
        "credentialSubject" => %{
          "id" => subject_id
        }
      }
    }
  end
end
