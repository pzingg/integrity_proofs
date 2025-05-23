defmodule DidServerWeb.Router do
  use DidServerWeb, :router

  import DidServerWeb.UserAuth

  pipeline :browser do
    plug(:accepts, ["html"])
    plug(:fetch_session)
    # plug :fetch_live_flash
    plug(:fetch_flash)
    plug(:put_root_layout, {DidServerWeb.Layouts, :root})
    plug(:protect_from_forgery)
    plug(:put_secure_browser_headers)
    plug(:fetch_current_user)
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

  ## Authentication routes

  scope "/", DidServerWeb do
    pipe_through :browser

    delete("/users/log_out", UserSessionController, :delete)
  end

  scope "/", DidServerWeb do
    pipe_through [:browser, :redirect_if_user_is_authenticated]

    get("/users/register", UserRegistrationController, :new)
    post("/users/register", UserRegistrationController, :create)

    get("/wauth/log_in", WebAuthnCredentialController, :new)
    post("/wauth/log_in", WebAuthnCredentialController, :create)

    get("/users/log_in", UserSessionController, :new)
    post("/users/log_in", UserSessionController, :create)
  end

  scope "/", DidServerWeb do
    pipe_through [:browser, :require_authenticated_user]

    get("/wauth/register", WebAuthnKeyController, :new)
    post("/wauth/register", WebAuthnKeyController, :create)

    get("/users/settings", UserSettingsController, :edit)
    put("/users/settings", UserSettingsController, :update)
  end

  scope "/users", DidServerWeb do
    pipe_through :dual

    get("/:handle", AccountsController, :actor)
  end

  scope "/users", DidServerWeb do
    pipe_through :plain

    get("/:handle/profile", AccountsController, :profile)
  end

  scope "/home", DidServerWeb do
    pipe_through :browser

    get("/", PageController, :home)
  end

  scope "/plc", DidServerWeb do
    pipe_through :api

    get("/_health", DidPlcController, :health)
    # get "/export", DidPlcController, :index

    get("/:did/data", DidPlcController, :did_data)
    get("/:did/log", DidPlcController, :active_log)
    get("/:did/log/audit", DidPlcController, :audit_log)
    get("/:did/log/last", DidPlcController, :last_operation)

    get("/:did", DidPlcController, :show)
    post("/:did", DidPlcController, :create)

    get("/", DidPlcController, :info)
  end

  # didkit operations
  scope "/", DidServerWeb do
    pipe_through :api

    get "/keys/new", KeyStoreController, :new
    post "/keys/create", KeyStoreController, :create
    get "/keys/show/:public_key", KeyStoreController, :show
    post "/keys/show", KeyStoreController, :show

    post "/credential/example", CredentialController, :example
    post "/credential/issue", CredentialController, :issue
    post "/credential/verify", CredentialController, :verify

    post "/presentation/prove", PresentationController, :prove
    post "/presentation/verify", PresentationController, :verify
  end

  scope "/.well-known", DidServerWeb do
    pipe_through :plain

    get("/atproto-did", DidPlcController, :domain_did)
  end

  scope "/.well-known", DidServerWeb do
    pipe_through :api

    get("/did.json", DidWebController, :domain_did)
  end

  # Root wildcard - must be at the end of the search
  scope "/", DidServerWeb do
    pipe_through :api

    get("/*path", DidWebController, :show)
  end
end
