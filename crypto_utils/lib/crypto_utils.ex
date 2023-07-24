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
  Formats a bitstring into am easy-to-read representation
  for debugging or assertions.

  ## Examples

      iex> display_bytes(<<15, 24>>)
      "<<15, 24>>"

      iex> display_bytes(<<15, 24>>, base: 16)
      "<<0x0F, 0x18>>"

  """
  def display_bytes(bin, opts \\ []) do
    base = Keyword.get(opts, :base, 10)
    start = Keyword.get(opts, :start, 0)
    length = Keyword.get(opts, :length, 0)
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

  @doc """
  Formats a did:plc operation for debugging purposes.
  """
  def display_op(%{"type" => type, "prev" => prev}) do
    prev = prev || "nil"
    "type #{type} prev #{prev}"
  end

  # %Operation{}
  def display_op(%{did: did, cid: cid, operation: operation}) do
    %{"type" => type, "prev" => prev} = Jason.decode!(operation)
    prev = prev || "nil"
    "type #{type} prev #{prev} did #{display_did(did)} cid #{cid} "
  end

  # %CreateParams{}
  def display_op(%{did: did, type: type, prev: prev}) do
    prev = prev || "nil"
    "type #{type} prev #{prev} did #{display_did(did)}"
  end

  @doc """
  Slices the first eight characters of a did's method-specific id
  for debugging purposes.
  """
  def display_did(nil), do: "null"

  def display_did(did) when is_binary(did) do
    [_, _, specific_id] = String.split(did, ":", parts: 3)
    String.slice(specific_id, 0, 8)
  end

  def display_did(did) when is_list(did) do
    Enum.map(did, &display_did/1) |> Enum.join(", ")
  end

  @doc """
  Prepends "http://" or "https://" to a URI if necessary.
  """
  def ensure_http_prefix(str, scheme \\ "https") do
    if String.starts_with?(str, "http://") || String.starts_with?(str, "https://") do
      str
    else
      scheme <> "://" <> str
    end
  end

  @doc """
  Prepends "at://" to a URI if necessary, after removing
  any existing "http://" or "https://" prefix.
  """
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

  @doc """
  Removes :authority, :userinfo, and :port after parsing a URI.
  Leaves :scheme, :host, :path, :query, and :fragment unchanged.
  """
  def to_uri(url) when is_binary(url) do
    %URI{port: port} = uri = URI.parse(url)

    port =
      case port do
        80 -> nil
        443 -> nil
        p when is_integer(p) -> p
        _ -> nil
      end

    %URI{uri | authority: nil, userinfo: nil, port: port}
  end

  @doc """
  Removes :authority, :userinfo, :port, :query, and :fragment from a URI.
  Leaves :scheme and :host unchanged.
  Sets :path if `path` is not nil, otherwise leaves it unchanged.
  """
  def base_uri(uri, path \\ nil)

  def base_uri(uri, path) when is_binary(uri) do
    to_uri(uri) |> base_uri(path)
  end

  def base_uri(%URI{} = uri, path) when is_binary(path) do
    %URI{uri | path: path, authority: nil, fragment: nil, query: nil, userinfo: nil}
  end

  def base_uri(%URI{} = uri, nil) do
    %URI{uri | authority: nil, fragment: nil, query: nil, userinfo: nil}
  end

  @doc """
  Returns `true` if a binary or URI has an "http" or "https"
  scheme with non-empty host and path components.
  """
  def http_uri?(url) when is_binary(url) do
    URI.parse(url) |> http_uri?()
  end

  def http_uri?(%URI{scheme: scheme, host: host, path: path} = _uri) do
    Enum.member?(["http", "https"], scheme) && !is_nil(host) && host != "" &&
      !is_nil(path) && String.length(path) > 1
  end

  def http_uri?(_), do: false

  @doc """
  Returns `true` if a binary or URI is a recognized DID method
  that has a non-empty method-specific id.
  """
  def did_uri?(url) when is_binary(url) do
    URI.parse(url) |> did_uri?()
  end

  def did_uri?(%URI{scheme: "did", host: nil, path: path})
      when is_binary(path) do
    case String.split(path, ":") do
      [did_method | [did_value | _]] ->
        did_method in CryptoUtils.Did.valid_did_methods() && did_value != ""

      _ ->
        false
    end
  end

  def did_uri?(_), do: false

  @doc """
  Returns `true` if a binary or URI has the scheme "at://" and
  there are username and domain parts in the `:host` component.
  """
  def atproto_uri?(url) when is_binary(url) do
    URI.parse(url) |> atproto_uri?()
  end

  def atproto_uri?(%URI{scheme: "at", host: host, path: nil})
      when is_binary(host) do
    String.contains?(host, ".")
  end

  def atproto_uri?(_), do: false
end
