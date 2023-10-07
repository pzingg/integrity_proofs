defmodule CryptoUtils.Did.ResolutionInputMetadata do
  @moduledoc """
  [DID Resolution Options](https://www.w3.org/TR/did-core/#did-resolution-options).

  Used as input to `DIDResolver::resolve/2`.
  """

  defstruct [
    :accept,
    :version_id,
    :version_time,
    :no_cache,
    property_set: %{}
  ]

  @type t() :: %__MODULE__{
          accept: String.t() | nil,
          version_id: String.t() | nil,
          version_time: String.t() | nil,
          no_cache: bool() | nil,
          property_set: map()
        }
end
