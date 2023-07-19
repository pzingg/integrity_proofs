defmodule CryptoUtils do
  @moduledoc """
  Functions that do some tricky modular math for
  use in finding points on an elliptic curve,
  functions for parsing and formatting public and private keys,
  and functions for decoding and encoding DIDs and CIDs.
  """

  defmodule InvalidPublicKeyError do
    defexception [:multibase, :reason]

    @impl true
    def message(%{multibase: multibase, reason: reason}) do
      "Invalid public Multikey #{multibase}: #{reason}"
    end
  end

  defmodule UnsupportedNamedCurveError do
    defexception [:message]

    @impl true
    def exception(name) do
      %__MODULE__{message: "unsupported named curve #{name}"}
    end
  end

  @doc """
  Parses an integer value from hexadecimal encoded string.

  ## Examples

      iex> parse_hex("f")
      15

  """
  def parse_hex(s) when is_binary(s) do
    case Integer.parse(s, 16) do
      {i, ""} -> i
      :error -> raise "could not parse"
    end
  end

  @doc """
  Formats a big integer (< 2 ^ 256) into a nul-padded
  32-byte bitstring.

  ## Examples

      iex> to_hex_32(15)
      <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15>>

  """
  def to_hex_32(i) do
    s = :binary.encode_unsigned(i)
    n_bytes = byte_size(s)

    if n_bytes < 32 do
      pad_size = (32 - n_bytes) * 8
      <<0::integer-size(pad_size)>> <> s
    else
      s
    end
  end

  @doc """
  Formats bitstring into a easy to read representation
  for debugging or assertions.

  ## Examples

      iex> display_bytes(<<15, 24>>)
      "<<15, 24>>"

      iex> display_bytes(<<15, 24>>, 16)
      "<<0x0F, 0x18>>"

  """
  def display_bytes(bin, base \\ 10, start \\ 0, length \\ 0) do
    bytes = :binary.bin_to_list(bin)

    bytes =
      if length > 0 do
        Enum.slice(bytes, start, length)
      else
        bytes
      end

    out =
      Enum.map(bytes, fn i ->
        case base do
          10 -> Integer.to_string(i, 10)
          16 -> "0x" <> (Integer.to_string(i, 16) |> String.pad_leading(2, "0"))
        end
      end)
      |> Enum.join(", ")

    "<<" <> out <> ">>"
  end

  def display_op(%{"prev" => prev, "rotationKeys" => rotation_keys}) do
    "prev #{prev} rotation_keys #{inspect(Enum.map(rotation_keys, &display_did(&1)))}"
  end

  def display_did(nil), do: "null"

  def display_did(did) do
    [_, _, specific_id] = String.split(did, ":", parts: 3)
    String.slice(specific_id, 0, 8)
  end

  def ensure_http_prefix(str) do
    if String.starts_with?(str, "http://") || String.starts_with?(str, "https://") do
      str
    else
      "https://" <> str
    end
  end

  def ensure_atproto_prefix(str) do
    if String.starts_with?(str, "at://") do
      str
    else
      "at://" <>
        (str
         |> String.replace_leading("http://", "")
         |> String.replace_leading("https://", ""))
    end
  end
end
