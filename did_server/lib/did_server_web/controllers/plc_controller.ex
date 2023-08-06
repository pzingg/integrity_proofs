defmodule DidServerWeb.PlcController do
  use DidServerWeb, :controller

  alias DidServer.Log.Operation
  alias DidServerWeb.ErrorJSON

  def info(conn, _params) do
    # HTTP temporary redirect to project git repo
    # res.redirect(302, 'https://github.com/bluesky-social/did-method-plc')
    render(conn, :info,
      info: %{
        name: DidServer.Application.name(),
        version: DidServer.Application.version(),
        services: DidServer.Application.services()
      }
    )
  end

  def health(conn, _params) do
    version = DidServer.Application.version()

    if DidServer.Log.health_check() do
      render(conn, :health, version: version)
    else
      conn
      |> put_status(503)
      |> render(:health, version: version, error: "Service Unavailable")
    end
  end

  @doc """
  Creates or updates a DID document.
  """
  def create(conn, %{"did" => did, "prev" => nil} = params) do
    try do
      with {:ok, %{operation: %{did: op_did}}} <- DidServer.Log.create_operation(params),
           {:verified, nil} <-
             {:verified,
              if did == op_did do
                nil
              else
                op_did
              end} do
        json(conn, "")
      else
        {:verified, op_did} ->
          render_error(conn, 400, "calculated did #{op_did} differs")

        {:error, %Ecto.Changeset{errors: [{field, {message, _keys}} | _]}} ->
          render_error(conn, 400, "#{field} #{message}")

        {:error, reason} ->
          render_error(conn, 400, reason)
      end
    rescue
      e -> render_error(conn, 400, Exception.message(e))
    end
  end

  def create(conn, %{"did" => did, "prev" => prev} = params) do
    try do
      with {:prev, op} when is_map(op) <- {:prev, DidServer.Log.get_operation_by_cid(did, prev)},
           {:ok, %{operation: %{did: op_did}}} <- DidServer.Log.update_operation(op, params),
           {:verified, nil} <-
             {:verified,
              if did == op_did do
                nil
              else
                op_did
              end} do
        json(conn, "")
      else
        {:prev, _} ->
          render_error(conn, 400, "previous operation not found")

        {:verified, op_did} ->
          render_error(conn, 400, "calculated did #{op_did} differs")

        {:error, %Ecto.Changeset{errors: [{field, {message, _keys}} | _]}} ->
          render_error(conn, 400, "#{field} #{message}")

        {:error, reason} ->
          render_error(conn, 400, reason)
      end
    rescue
      e -> render_error(conn, 400, Exception.message(e))
    end
  end

  def domain_did(conn, _params) do
    did = DidServer.Identities.get_domain_key()
    render_did_document_or_error(conn, did)
  end

  def show(conn, %{"did" => did}) do
    render_did_document_or_error(conn, did)
  end

  @doc """
  Gets the operation log for a DID.
  """
  def active_log(conn, %{"did" => did}) do
    ops = DidServer.Log.list_operations(did, false)

    if Enum.empty?(ops) do
      render_error(conn, 404, "DID not registered: #{did}")
    else
      ops = Enum.map(ops, &Operation.to_json_data/1)
      render(conn, :log, operations: ops)
    end
  end

  @doc """
  Gets the operation log for a DID, including forked history.
  """
  def audit_log(conn, %{"did" => did}) do
    ops = DidServer.Log.list_operations(did, true)

    if Enum.empty?(ops) do
      render_error(conn, 404, "DID not registered: #{did}")
    else
      ops = Enum.map(ops, &Operation.to_json_data/1)
      render(conn, :log, operations: ops)
    end
  end

  @doc """
  Gets the most recent operation in the log for a DID.
  """
  def last_operation(conn, %{"did" => did}) do
    case DidServer.Log.get_last_op(did, :data) do
      data when is_map(data) ->
        render(conn, :operation, operation: data)

      _ ->
        render_error(conn, 404, "DID not registered: #{did}")
    end
  end

  @doc """
  Gets the data for a DID document.
  """
  def did_data(conn, %{"did" => did}) do
    case DidServer.Log.get_last_op(did, :did_data) do
      data when is_map(data) ->
        render(conn, :operation, operation: data)

      _ ->
        render_error(conn, 404, "DID not registered: #{did}")
    end
  end

  def render_did_document_or_error(conn, did) do
    case DidServer.Identities.format_did_document(did) do
      nil ->
        render_error(conn, 404, "DID not registered: #{did}")

      doc ->
        conn
        |> put_resp_content_type("application/did+ld+json")
        |> render(:did_document, document: doc)
    end
  end

  def render_error(conn, status_code, reason) do
    conn
    |> put_status(status_code)
    |> put_view(ErrorJSON)
    |> render("#{status_code}.json", detail: reason)
  end
end
