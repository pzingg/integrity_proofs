defmodule CryptoUtils.Proof.ProofOptions do
  defstruct [
    :proof_format,
    :type,
    :verification_method,
    :proof_purpose,
    :created,
    :challenge,
    :domain,
    :checks
    # :eip712_domain
  ]

  @type t() :: %__MODULE__{
          proof_format: CryptoUtils.Proof.ProofFormat.t(),
          type: String.t() | nil,
          verification_method: URI.t() | nil,
          proof_purpose: CryptoUtils.Proof.ProofPurpose.t() | nil,
          created: NaiveDateTime.t() | nil,
          challenge: String.t() | nil,
          domain: String.t() | nil,
          checks: [CryptoUtils.Proof.Check.t()] | nil
          # eip712_domain: ProofInfo.t() | nil
        }
end
