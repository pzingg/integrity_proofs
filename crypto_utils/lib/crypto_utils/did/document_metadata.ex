defmodule CryptoUtils.Did.DocumentMetadata do
  @moduledoc """
  Metadata structure describing a DID document in a DID Resolution Result.

  Specified:
  - in [DID Core](https://www.w3.org/TR/did-core/#dfn-diddocumentmetadata)
  - in [DID Resolution](https://w3c-ccg.github.io/did-resolution/#output-documentmetadata)
  - in [DID Specification Registries](https://www.w3.org/TR/did-spec-registries/#did-document-metadata)
  """

  defstruct [
    :created,
    :updated,
    :deactivated,
    property_set: %{}
  ]

  @type t() :: %__MODULE__{
          created: NaiveDateTime.t() | nil,
          updated: NaiveDateTime.t() | nil,
          deactivated: boolean() | nil,
          property_set: map()
        }
end
