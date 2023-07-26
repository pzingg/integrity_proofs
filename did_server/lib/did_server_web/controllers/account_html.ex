defmodule DidServerWeb.AccountHTML do
  use DidServerWeb, :html

  alias DidServer.Accounts.User

  embed_templates "account_html/*"
end
