# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

# Set up a database to record plc server logs
config :integrity_proofs,
  ecto_repos: [IntegrityProofs.Did.PlcRepo]

config :integrity_proofs, IntegrityProofs.Did.PlcRepo,
  url: "ecto://postgres:postgres@localhost/plc_log"
