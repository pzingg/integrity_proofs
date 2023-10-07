defmodule CryptoUtils.MixProject do
  use Mix.Project

  def project do
    [
      app: :crypto_utils,
      version: "0.1.0",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :crypto, :public_key, :ssh, :inets]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.4"},
      {:multibase, "~> 0.0.1"},
      {:multicodec, "~> 0.0.2"},
      {:cbor, "~> 1.0.0"},
      {:jose, "~> 1.11"},
      {:ecto, "~> 3.10"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
