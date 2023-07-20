defmodule DidServerWeb.Router do
  use DidServerWeb, :router

  import DidServerWeb.UserAuth

  pipeline :browser do
    plug(:accepts, ["html"])
    # plug :fetch_session
    # plug :fetch_live_flash
    plug(:put_root_layout, {DidServerWeb.Layouts, :root})
    # plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :fetch_current_user
  end

  pipeline :api do
    plug(:accepts, ["json"])
  end

  scope "/plc", DidServerWeb do
    pipe_through(:api)

    get("/_health", PlcController, :health)
    # get "/export", PlcController, :index
    # get "/:did/data", PlcController, :show_data
    # get "/:did/log", PlcController, :show_log
    # get "/:did/log/audit", PlcController, :show_operation_log
    # get "/:did/log", PlcController, :show_most_recent
    get("/:did", PlcController, :show)
    post "/:did", PlcController, :new

    get("/", PlcController, :info)
  end

  scope "/.well-known", DidServerWeb do
    pipe_through(:api)

    get("/did.json", WebController, :show_root)
  end

  ## Authentication routes

  scope "/", DidServerWeb do
    pipe_through [:browser, :redirect_if_user_is_authenticated]

    get "/users/register", UserRegistrationController, :new
    post "/users/register", UserRegistrationController, :create
    get "/users/log_in", UserSessionController, :new
    post "/users/log_in", UserSessionController, :create
    get "/users/reset_password", UserResetPasswordController, :new
    post "/users/reset_password", UserResetPasswordController, :create
    get "/users/reset_password/:token", UserResetPasswordController, :edit
    put "/users/reset_password/:token", UserResetPasswordController, :update
  end

  scope "/", DidServerWeb do
    pipe_through [:browser, :require_authenticated_user]

    get "/users/settings", UserSettingsController, :edit
    put "/users/settings", UserSettingsController, :update
    get "/users/settings/confirm_email/:token", UserSettingsController, :confirm_email
  end

  scope "/", DidServerWeb do
    pipe_through [:browser]

    delete "/users/log_out", UserSessionController, :delete
    get "/users/confirm", UserConfirmationController, :new
    post "/users/confirm", UserConfirmationController, :create
    get "/users/confirm/:token", UserConfirmationController, :edit
    post "/users/confirm/:token", UserConfirmationController, :update
  end

  scope "/home", DidServerWeb do
    pipe_through(:browser)

    get "/", PageController, :home
  end

  # Root wildcard - must be at the end of the search
  scope "/", DidServerWeb do
    pipe_through(:api)

    get("/*path", WebController, :show)
  end
end
