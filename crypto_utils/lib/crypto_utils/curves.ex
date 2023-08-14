defmodule CryptoUtils.Curves do
  @moduledoc """
  Basic math for points on the p256 and secp256k1 elliptic curves.
  """
  require Integer

  alias CryptoUtils.Math, as: CMath

  # Named elliptic curves
  @id_ed25519 {1, 3, 101, 112}
  @id_p256 {1, 2, 840, 10045, 3, 1, 7}
  @id_secp256k1 {1, 3, 132, 0, 10}

  @known_curves %{
    @id_ed25519 => :ed25519,
    @id_p256 => :p256,
    @id_secp256k1 => :secp256k1
  }

  # Curve initial parameters needed to decompress points
  @p256_params {"p256",
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
                |> CryptoUtils.parse_hex(),
                "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc"
                |> CryptoUtils.parse_hex(),
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"
                |> CryptoUtils.parse_hex()}

  @secp256k1_params {"secp256k1",
                     "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
                     |> CryptoUtils.parse_hex(), 0, 7}

  # COSE registry values for use with WebAuthn
  @cose_algs %{
    ed25519: %{name: "EdDSA", alg: -8, crv: 6, coord_type: "OKP"},
    p256: %{name: "ES256", alg: -7, crv: 1, coord_type: "EC2"},
    # Not sure if ES256K is supported in COSE
    secp256k1: %{name: "ES256K", alg: -47, crv: nil, coord_type: "EC2"}
  }

  @doc """
  Returns an atom identifying a named elliptic curve from an OID.
  """
  def curve_from_oid(curve_oid), do: Map.get(@known_curves, curve_oid)

  @doc """
  Returns the Erlang `:namedCurve` record containing the curve's OID.
  """
  def curve_params(curve)

  def curve_params(:ed25519), do: {:namedCurve, @id_ed25519}
  def curve_params(:p256), do: {:namedCurve, @id_p256}
  def curve_params(:secp256k1), do: {:namedCurve, @id_secp256k1}

  def erlang_ec_curve(:ed25519), do: :ed25519
  def erlang_ec_curve(:p256), do: :secp256r1
  def erlang_ec_curve(:secp256k1), do: :secp256k1

  def erlang_algo(:ed25519), do: :eddsa
  def erlang_algo(:p256), do: :ecdh
  def erlang_algo(:secp256k1), do: :ecdh

  def cose(curve) when is_atom(curve), do: Map.fetch!(@cose_algs, curve)

  def compress_public_key_point(<<mode::size(8), x_coord::binary-size(32), y_coord::binary>>) do
    test =
      case {mode, byte_size(y_coord)} do
        {4, 32} -> :ok
        {_, 32} -> {:error, "invalid mode #{mode}"}
        {_, n} -> {:error, "invalid size for uncompressed key #{n + 33}"}
      end

    with :ok <- test do
      if :binary.decode_unsigned(y_coord, :big) |> Integer.is_even() do
        {:ok, <<2>> <> x_coord}
      else
        {:ok, <<3>> <> x_coord}
      end
    end
  end

  def decompress_public_key_point(point, curve_oid) when is_tuple(curve_oid) do
    curve = curve_from_oid(curve_oid)

    if curve in [:p256, :secp256k1] do
      decompress_public_key_point(point, curve)
    else
      {:error, "invalid curve OID #{inspect(curve_oid)}"}
    end
  end

  def decompress_public_key_point(point, :p256) do
    decompress_curve_point(point, @p256_params)
  end

  def decompress_public_key_point(point, :secp256k1) do
    decompress_curve_point(point, @secp256k1_params)
  end

  def decompress_curve_point(<<4, _coords::binary>> = key_bytes, _)
      when byte_size(key_bytes) == 65 do
    {:ok, key_bytes}
  end

  def decompress_curve_point(<<mode::size(8), x_coord::binary>>, {_name, p, a, b}) do
    test =
      case {mode, byte_size(x_coord)} do
        {2, 32} -> {:ok, false}
        {3, 32} -> {:ok, true}
        {_, 32} -> {:error, "invalid mode #{mode}"}
        {_, n} -> {:error, "invalid size for compressed key #{n + 1}"}
      end

    with {:ok, odd?} <- test,
         x <- :binary.decode_unsigned(x_coord, :big),
         y_squared <- rem(CMath.mod_pow(x, 3, p) + a * x + b, p),
         {:ok, y} <- CMath.sqrt_mod(y_squared, p) do
      if odd? == Integer.is_odd(y) do
        {:ok, <<4::8>> <> CryptoUtils.to_hex_32(x) <> CryptoUtils.to_hex_32(y)}
      else
        {:ok, <<4::8>> <> CryptoUtils.to_hex_32(x) <> CryptoUtils.to_hex_32(p - y)}
      end
    end
  end
end
