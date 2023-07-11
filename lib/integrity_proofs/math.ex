defmodule IntegrityProofs.Math do
  require Integer

  @doc """
  Tonelli-Shanks algorithm to find modular square root.

  See:
  * https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
  * https://rosettacode.org/wiki/Tonelli-Shanks_algorithm#int
  * https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
  """
  def sqrt_mod(n, p) do
    ls = jacobi_symbol(n, p)

    if ls == 1 do
      # Step 1
      # By factoring out powers of 2, find q and s such that
      # p - 1 == q ^ (2 ^ s), with q odd
      {q, s} = find_q_and_s(p - 1, 0)

      # Step 2
      # Search for a z in Z/pZ which is a quadratic non-residue.
      z = non_quadratic_residue(2, p)

      # Step 3
      # Let c = z ^ q
      c = mod_pow(z, q, p)
      # Let t = n ^ q
      t = mod_pow(n, q, p)
      # Let r = n ^ (q + 1 / 2)
      r = mod_pow(n, div(q + 1, 2), p)
      # Let m = s
      ts_loop(t, r, s, c, p, 0)
    else
      {:error, "invalid jacobi: #{ls}"}
    end
  end

  def find_q_and_s(q, s) do
    if Bitwise.band(q, 1) == 1 do
      {q, s}
    else
      find_q_and_s(Bitwise.bsr(q, 1), s + 1)
    end
  end

  def non_quadratic_residue(z, p) do
    # See https://en.wikipedia.org/wiki/Jacobi_symbol
    if jacobi_symbol(z, p) == -1 do
      z
    else
      # Still a quadratic residue
      non_quadratic_residue(z + 1, p)
    end
  end

  def ts_loop(_t, _r, _m, _c, _p, iter) when iter >= 1000 do
    {:error, "exceeded"}
  end

  def ts_loop(0, _r, _m, _c, _p, _iter) do
    # Step 4.
    # If t == 0, return 0
    {:ok, 0}
  end

  def ts_loop(1, r, _m, _c, _p, _iter) do
    # Step 4.
    # If t == 1, return r
    {:ok, r}
  end

  def ts_loop(t, r, m, c, p, iter) do
    # Step 4.
    # Use repeated squaring to find the least i,
    # 0 < i < m, such that if z = t ^ (2 ^ i), z == 1
    i = least_i(0, t, m, p)

    # Let b = c ^ (2 ^ (m - i - 1))
    e = pow(2, m - i - 1)
    b = mod_pow(c, e, p)

    # Let c = b ^ 2
    c = rem(b * b, p)
    # Let t = t * b ^ 2
    t = rem(t * c, p)
    # Let r = r * b
    r = rem(r * b, p)
    # Let m = i
    ts_loop(t, r, i, c, p, iter + 1)
  end

  def least_i(i, z, m, p) do
    # Use repeated squaring to find the least i,
    # 0 < i < m, such that if z = t ^ (2 ^ i), z == 1
    if i == 0 || (i < m && z != 1) do
      least_i(i + 1, rem(z * z, p), m, p)
    else
      i
    end
  end

  def parse_hex(s) do
    case Integer.parse(s, 16) do
      {i, ""} -> i
      :error -> raise "could not parse"
    end
  end

  # From Chunky
  def pow(_x, 0), do: 1
  def pow(x, 1), do: x

  def pow(x, y) when is_integer(x) and is_integer(y) and y > 0 and Integer.is_even(y) do
    pow(x * x, div(y, 2))
  end

  def pow(x, y) when is_integer(x) and is_integer(y) do
    x * pow(x * x, div(y - 1, 2))
  end

  # From Chunky
  def jacobi_symbol(a, p) do
    case mod_pow(a, div(p - 1, 2), p) do
      1 -> 1
      0 -> 0
      _rem -> -1
    end
  end

  # From Chunky
  def mod_pow(x, 0, _p) when is_integer(x), do: 1

  def mod_pow(x, y, p) when is_integer(x) and is_integer(y) and y > 0 and is_integer(p) do
    #  a^e mod p
    :crypto.mod_pow(x, y, p) |> :binary.decode_unsigned()
  end

  def display_bytes(bin) do
    out =
      :binary.bin_to_list(bin)
      |> Enum.map(&Integer.to_string(&1))
      |> Enum.join(", ")

    "<<" <> out <> ">>"
  end
end
