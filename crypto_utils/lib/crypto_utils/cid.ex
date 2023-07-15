defmodule CryptoUtils.Cid do
  @moduledoc """
  Cids as implemented in AT Protocol. Existing Elixir multiformats and
  Cid libraries do not yet seem to support "dag-cbor".

  1. JSON data (map) is dag-cbor encoded
  2. `multihash` of `:sha2_256` digest is then `<<18, len, digest::binary>>`
  3. `version` is always 1
  4. `codec` is always "dag-cbor"

  For string representation

  1. raw Cid binary is `<<1, 113, multihash::binary>>` (version 1, codec 113)
  2. raw binary is multibase base-32 lowercase encoded ("b" prefix)
  """

  defstruct [:codec, :multihash, :version]

  @type t() :: %__MODULE__{
          codec: String.t(),
          multihash: binary(),
          version: integer()
        }

  # Multihash code 18
  @sha2_256_code 0x12
  # Multicodec code 113
  @dag_cbor_code 0x71

  @doc """
  Creates a Cid struct from JSON data (map).
  """
  def from_data(data) when is_map(data) do
    CBOR.encode(data) |> from_cbor()
  end

  @doc """
  Creates a Cid struct from a CBOR-encoded binary.
  """
  def from_cbor(cbor) when is_binary(cbor) do
    digest = :crypto.hash(:sha256, cbor)
    multihash = <<@sha2_256_code, byte_size(digest), digest::binary>>
    new(multihash)
  end

  @doc """
  Creates a Cid struct from a multihash.
  """
  def new(multihash, codec \\ "dag-cbor", version \\ 1) do
    %__MODULE__{codec: codec, multihash: multihash, version: version}
  end

  @doc """
  Returns a base-32 lowercase string representation of the Cid.
  The returned value always starts with "b".

  If the option `:truncate` is set to an positive integer value
  (AT protocol uses 24), the string returned will be truncated
  to that many characters.
  """
  def encode!(cid, options \\ [])

  def encode!(%__MODULE__{codec: "dag-cbor", multihash: multihash, version: 1}, options) do
    full =
      <<1, @dag_cbor_code, multihash::binary>>
      |> Multibase.encode!(:base32_lower)

    case Keyword.get(options, :truncate) do
      length when is_integer(length) and length > 1 ->
        String.slice(full, 0, length)

      _ ->
        full
    end
  end

  @doc """
  Decodes a base-32 lowercase string representation into a Cid struct.
  The string must always start with "b".
  """
  def decode!(str) do
    case Multibase.codec_decode!(str) do
      {<<1, @dag_cbor_code, multihash::binary>>, :base32_lower} ->
        %__MODULE__{codec: "dag-cbor", multihash: multihash, version: 1}

      {<<1, code, _multihash::binary>>, :base32_lower} ->
        raise ArgumentError, message: "invalid Multihash code #{code}, expected 113"

      {<<version, _rest::binary>>, :base32_lower} ->
        raise ArgumentError, message: "invalid version #{version}, expected 1"

      {_bin, code} ->
        raise ArgumentError, message: "invalid Multibase code #{code}, expected 'b'"
    end
  end
end

defimpl String.Chars, for: CryptoUtils.Cid do
  @impl true
  def to_string(%CryptoUtils.Cid{} = cid), do: CryptoUtils.Cid.encode!(cid, [])
end
