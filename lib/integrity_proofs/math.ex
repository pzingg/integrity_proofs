defmodule IntegrityProofs.Math do
  require Integer

  def sqrt_mod(n, p) do
    ls = legendre_symbol(n, p)

    if ls == 1 do
      # WP step 1, factor out powers of two
      {q, s} = q_s_(p - 1, 0)

      # WP step 1, direct solution
      if s == 1 do
        r = mod_pow(n, div(p, 4), p)
        {:ok, r}
      else
        # WP step 2, select z, assign c
        z = z_(2, p)
        c = mod_pow(z, q, p)

        # WP step 3, assign R, t, M
        t = mod_pow(n, q, p)
        r = mod_pow(n, div(q + 1, 2), p)

        # WP step 4, loop
        ts_loop(t, r, s, c, p)
      end
    else
      {:error, "invalid legendre symbol: #{ls}"}
    end
  end

  def q_s_(q, s) do
    if Bitwise.band(q, 1) == 0 do
      q_s_(Bitwise.bsr(q, 1), s + 1)
    else
      {q, s}
    end
  end

  def z_(z, p) do
    if legendre_symbol(z, p) != -1 do
      z_(z + 1, p)
    else
      z
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

  def ts_loop(1, r, _m, _c, _p) do
    # WP step 4.1, termination condition
    {:ok, r}
  end

  def ts_loop(t, r, m, c, p) do
    # WP step 4.2, find lowest i...
    i = lowest_i(0, t, m, p)

    # WP step 4.3, using a variable b, assign new values of R, t, c, M
    b = Enum.reduce(1..(m - i - 1)//1, c, fn _e, b -> div(b * b, p) end)
    r = div(r * b, p)
    # more convenient to compute c before t
    c = div(b * b, p)
    t = div(t * c, p)
    ts_loop(t, r, i, c, p)
  end

  def lowest_i(i, z, m, p) do
    if z != 1 && i < m - 1 do
      lowest_i(i + 1, rem(z * z, p), m, p)
    else
      i
    end
  end
end
