defmodule CryptoUtils.Did.ResolutionMetadata do
  @moduledoc """
  [DID Resolution Metadata](https://www.w3.org/TR/did-core/#did-resolution-metadata)

  Specified in [DID Resolution](https://w3c-ccg.github.io/did-resolution/#output-resolutionmetadata)
  """

  defstruct [
    :error,
    :content_type,
    property_set: %{}
  ]

  @type t() :: %__MODULE__{
          error: String.t() | nil,
          content_type: String.t() | nil,
          property_set: map()
        }

  def new_error(error) do
    %__MODULE__{error: error}
  end
end
