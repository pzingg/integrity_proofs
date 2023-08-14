defmodule DidServerWeb.PageController do
  use DidServerWeb, :controller

  def home(conn, _params) do
    # If your home page is custom made, with special menus, etc.
    # add the `layout: false` keyword to skip the default app layout.
    render(conn, :home)
  end
end
