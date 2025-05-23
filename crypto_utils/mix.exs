defmodule CryptoUtils.MixProject do
  use Mix.Project

  def project do
    [
      app: :crypto_utils,
      version: "0.2.0",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
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

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.4"},
      {:multibase, "~> 0.0.1"},
      {:multicodec, "~> 0.0.2"},
      {:cbor, "~> 1.0.0"},
      {:jose, "~> 1.11"},
      {:ecto, "~> 3.10"},
      {:plug, "~> 1.17"},
      {:req, "~> 0.5"}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
