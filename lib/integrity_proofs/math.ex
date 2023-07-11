defmodule IntegrityProofs.Math do
  require Integer

  @doc """
  Tonelli-Shanks algorithm to find modular square root.

  See: https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
  """
  def sqrt_mod(n, p) do
    ls = legendre_symbol(n, p)

    if ls == 1 do
      # Step 1
      # By factoring out powers of 2, find q and s such that
      # p - 1 == q * 2 ^ 2, with q odd

      {q, s} = find_q_and_s(p - 1, 0)

      # WP step 1, direct solution
      if s == 1 do
        r = mod_pow(n, div(p, 4), p)
        {:ok, r}
      else
        # Step 2
        # Search for a z in Z/pZ which is a quadratic non-reside.

        z = find_non_quadratic_z(2, p)
        c = mod_pow(z, q, p)

        # WP step 3, assign R, t, M
        t = mod_pow(n, q, p)
        r = mod_pow(n, div(q + 1, 2), p)

        # Step 4, loop
        ts_loop(t, r, s, c, p)
      end
    else
      {:error, "invalid legendre symbol: #{ls}"}
    end
  end

  def find_q_and_s(q, s) do
    if Bitwise.band(q, 1) == 0 do
      find_q_and_s(Bitwise.bsr(q, 1), s + 1)
    else
      {q, s}
    end
  end

  def find_non_quadratic_z(z, p) do
    # Find the Jacobi symbol
    if legendre_symbol(z, p) != -1 do
      find_non_quadratic_z(z + 1, p)
    else
      z
    end
  end

  def ts_loop(0, _r, _m, _c, _p) do
    # If t == 0, return 0
    {:ok, 0}
  end

  def ts_loop(1, r, _m, _c, _p) do
    # If t == 1, return r
    {:ok, r}
  end

  def ts_loop(t, r, m, c, p) do
    i = lowest_i(0, t, m, p)
    IO.puts("lowest_i #{i}")

    # Let b = c ^ (2 ^ (m - i - 1))
    b = Enum.reduce(1..(m - i - 1)//1, c, fn _e, b -> div(b * b, p) end)
    # Let c = b ^ 2
    c = div(b * b, p)
    # Let t = t * b ^ 2
    t = div(t * c, p)
    # Let r = r * b
    r = div(r * b, p)
    # Let m = i
    ts_loop(t, r, i, c, p)
  end

  def lowest_i(i, z, m, p) do
    # Use repeated squaring to find the least i,
    # 0 < i < m, such that if z = t ^ (2 ^ i), z == 1
    if i < m - 1 && z == 1 do
      i
    else
      lowest_i(i + 1, rem(z * z, p), m, p)
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
  def legendre_symbol(a, p) do
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
end
