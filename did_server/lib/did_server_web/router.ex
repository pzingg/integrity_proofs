defmodule DidServerWeb.Router do
  use DidServerWeb, :router

  pipeline :browser do
    plug(:accepts, ["html"])
    # plug :fetch_session
    # plug :fetch_live_flash
    plug(:put_root_layout, {DidServerWeb.Layouts, :root})
    # plug :protect_from_forgery
    # plug :put_secure_browser_headers
  end

  pipeline :api do
    plug(:accepts, ["json"])
  end

  scope "/home", DidServerWeb do
    pipe_through(:browser)

    get "/", PageController, :home
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

  scope "/", DidServerWeb do
    pipe_through(:api)

    get("/*path", WebController, :show)
  end
end
