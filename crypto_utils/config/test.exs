import Config

# Req.Test stubs
config :crypto_utils, :did_web_req_options, plug: {Req.Test, DidWebStub}
config :crypto_utils, :did_plc_req_options, plug: {Req.Test, DidPlcStub}

# Print only warnings and errors during test
config :logger, level: :warning
