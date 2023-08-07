defmodule DidServerWeb.AccountsHTML do
  use DidServerWeb, :html

  alias DidServer.Accounts.Account

  embed_templates "accounts_html/*"
end
