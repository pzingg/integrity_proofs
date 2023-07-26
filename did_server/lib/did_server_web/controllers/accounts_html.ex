defmodule DidServerWeb.AccountsHTML do
  use DidServerWeb, :html

  alias DidServer.Accounts.User

  embed_templates "accounts_html/*"
end
