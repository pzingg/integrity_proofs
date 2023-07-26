defmodule DidServerWeb.Router do
  use DidServerWeb, :router

  # import DidServerWeb.UserAuth

  pipeline :browser do
    plug(:accepts, ["html"])
    # plug :fetch_session
    # plug :fetch_live_flash
    plug(:put_root_layout, {DidServerWeb.Layouts, :root})
    # plug :protect_from_forgery
    # plug :put_secure_browser_headers
    # plug :fetch_current_user
  end

  pipeline :plain do
    plug(:accepts, ["text", "html"])
  end

  pipeline :api do
    plug(:accepts, ["json"])
  end

  pipeline :dual do
    plug(:accepts, ["html", "json"])
  end

  scope "/plc", DidServerWeb do
    pipe_through(:api)

    get "/_health", PlcController, :health
    # get "/export", PlcController, :index

    get "/:did/data", PlcController, :did_data
    get "/:did/log", PlcController, :active_log
    get "/:did/log/audit", PlcController, :audit_log
    get "/:did/log/last", PlcController, :last_operation

    get "/:did", PlcController, :show
    post "/:did", PlcController, :create

    get "/", PlcController, :info
  end

  scope "/.well-known", DidServerWeb do
    pipe_through(:api)

    get "/did.json", WebController, :domain_did
  end

  scope "/.well-known", DidServerWeb do
    pipe_through(:plain)

    get "/atproto-did", PlcController, :domain_did
  end

  ## Authentication routes
  # TODO

  scope "/user", DidServerWeb do
    pipe_through(:dual)

    get "/:handle", AccountController, :actor
    get "/:handle/profile", AccountController, :actor
  end

  scope "/home", DidServerWeb do
    pipe_through(:browser)

    get "/", PageController, :home
  end

  # Root wildcard - must be at the end of the search
  scope "/", DidServerWeb do
    pipe_through(:api)

    get "/*path", WebController, :show
  end
end
