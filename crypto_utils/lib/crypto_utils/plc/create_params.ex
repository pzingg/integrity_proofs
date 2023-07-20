defmodule CryptoUtils.Plc.CreateParams do
  defstruct [
    :did,
    :type,
    :prev,
    :sig,
    :verification_methods,
    :rotation_keys,
    :also_known_as,
    :services,
    :password
  ]
end
