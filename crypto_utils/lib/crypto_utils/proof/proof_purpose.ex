defmodule CryptoUtils.Proof.ProofPurpose do
  @type t() ::
          :assertion_method
          | :authentication
          | :key_agreement
          | :contract_agreement
          | :capability_delegation
end
