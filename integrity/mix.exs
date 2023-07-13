defmodule IntegrityProofs.MixProject do
  use Mix.Project

  def project do
    [
      app: :integrity_proofs,
      version: "0.1.0",
      elixir: "~> 1.14",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      mod: {IntegrityProofs.Application, []},
      extra_applications: [:logger, :crypto, :public_key, :ssh]
    ]
  end

  # Specifies which paths to compile per environment.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:jason, "~> 1.4"},
      {:ecto_sql, "~> 3.6"},
      {:postgrex, ">= 0.0.0"},
      {:multibase, "~> 0.0.1"},
      {:multicodec, "~> 0.0.2"},
      {:cbor, "~> 1.0.0"},
      {:jcs, git: "https://github.com/pzingg/jcs.git"},
      {:test_server, "~> 0.1", only: :test}
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"}
    ]
  end
end
