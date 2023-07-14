defmodule CryptoUtils do
  @moduledoc """
  Definition of a CID, and some tricky math
  to use in finding points on an elliptic curve.
  """

  defmodule InvalidDidError do
    defexception [:message]

    @impl true
    def exception(did) do
      %__MODULE__{message: "Invalid DID #{did}"}
    end
  end

  defmodule InvalidPublicKeyError do
    defexception [:multibase, :reason]

    @impl true
    def message(%{multibase: multibase, reason: reason}) do
      "Invalid public Multikey #{multibase}: #{reason}"
    end
  end

  defmodule UnexpectedDidMethodError do
    defexception [:message]

    @impl true
    def exception(method) do
      %__MODULE__{message: "Unexpected DID method #{method}"}
    end
  end

  defmodule UnsupportedNamedCurveError do
    defexception [:message]

    @impl true
    def exception(name) do
      %__MODULE__{message: "unsupported named curve #{name}"}
    end
  end

  def parse_hex(s) do
    case Integer.parse(s, 16) do
      {i, ""} -> i
      :error -> raise "could not parse"
    end
  end

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

  def display_bytes(bin) do
    out =
      :binary.bin_to_list(bin)
      |> Enum.map(&Integer.to_string(&1))
      |> Enum.join(", ")

    "<<" <> out <> ">>"
  end
end
