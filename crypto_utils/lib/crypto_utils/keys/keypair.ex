defmodule CryptoUtils.Keys.Keypair do
  @moduledoc """
  Encapsulates a public / private keypair for one of
  our supported ec or ed curves.
  """

  defstruct [:public_key, :private_key, :public_key_format, :private_key_format]

  def new(key_4_tuple)

  def new({public_key, private_key, public_key_format, private_key_format})
      when is_atom(public_key_format) and is_atom(private_key_format) do
    %__MODULE__{
      public_key: public_key,
      private_key: private_key,
      public_key_format: public_key_format,
      private_key_format: private_key_format
    }
  end

  @doc """
  Generates a new random public-private key pair. `public_key_format` determines the
  format of the keys returned. See `make_public_key/3`
  and `make_private_key/3` for details on the return
  formats.
  """
  def generate(curve, public_key_format) do
    CryptoUtils.Keys.generate_keypair(curve, public_key_format)
    |> new()
  end

  def decode_pem_ssh_file(pem, type \\ :openssh_key_v1) do
    case CryptoUtils.Keys.decode_pem_ssh_file(pem, type, :did_key) do
      {:ok, did, private_key} -> {:ok, new({did, private_key, :did_key, :crypto_algo_key})}
      error -> error
    end
  end

  def decode_pem_public_key(pem) do
    case CryptoUtils.Keys.decode_pem_public_key(pem, :did_key) do
      {:ok, did, private_key} -> {:ok, new({did, private_key, :did_key, :crypto_algo_key})}
      error -> error
    end
  end

  @doc """
  Returns the public key did for the keypair.
  """
  def did(%__MODULE__{public_key: did, public_key_format: :did_key}), do: did

  def encode_pem_public_key(%__MODULE__{
        public_key: did,
        public_key_format: :did_key
      }) do
    CryptoUtils.Keys.encode_pem_public_key(did)
  end

  def encode_pem_public_key(%__MODULE__{
        public_key: ec_point,
        public_key_format: :public_key
      }) do
    CryptoUtils.Keys.encode_pem_public_key(ec_point)
  end

  def encode_pem_private_key(%__MODULE__{
        private_key: ec_private_key,
        private_key_format: :public_key
      }) do
    CryptoUtils.Keys.encode_pem_private_key(ec_private_key)
  end

  def encode_pem_private_key(%__MODULE__{
        public_key: did,
        private_key: crypto_algo_key,
        public_key_format: :did_key,
        private_key_format: :crypto_algo_key
      }) do
    CryptoUtils.Keys.encode_pem_private_key({did, crypto_algo_key})
  end

  @doc """
  Formats a `:did_key` / `:crypto_algo_key` keypair into a JSON-compatible
  flattened list of strings.
  """
  def to_json(%__MODULE__{
        public_key: did,
        private_key: {algorithm, [priv, curve]},
        public_key_format: :did_key,
        private_key_format: :crypto_algo_key
      }) do
    [did, to_string(algorithm), priv, to_string(curve)]
  end
end
