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
  Updates or creates a DID document.
  """
  def create(conn, %{"did" => did} = params) do
    params =
      case DidServer.Log.get_last_op(did) do
        %{cid: cid} -> Map.put(params, "prev", cid)
        _ -> Map.put(params, "prev", nil)
      end

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
  end

  def domain_did(conn, _params) do
    did = DidServer.Log.get_domain_key()

    case format_did_document(did) do
      {:ok, doc} ->
        conn
        |> put_resp_content_type("application/did+ld+json")
        |> render(:did_document, document: doc)

      {:error, reason} ->
        render_error(conn, 404, reason)
    end
  end

  def show(conn, %{"did" => did}) do
    case format_did_document(did) do
      {:ok, doc} ->
        conn
        |> put_resp_content_type("application/did+ld+json")
        |> render(:did_document, document: doc)

      {:error, reason} ->
        render_error(conn, 404, reason)
    end
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
    with {:registered, %Operation{} = op} = {:registered, DidServer.Log.get_last_op(did)},
         {:valid, data} when is_map(data) <- {:valid, Operation.to_json_data(op)} do
      render(conn, :operation, operation: data)
    else
      {:registered, _} ->
        render_error(conn, 404, "DID not registered: #{did}")

      {:valid, _} ->
        render_error(conn, 404, "DID has been revoked: #{did}")
    end
  end

  @doc """
  Gets the data for a DID document.
  """
  def did_data(conn, %{"did" => did}) do
    with {:registered, %Operation{} = op} = {:registered, DidServer.Log.get_last_op(did)},
         {:valid, data} when is_map(data) <- {:valid, CryptoUtils.Did.to_data(op)} do
      render(conn, :operation, operation: data)
    else
      {:registered, _} ->
        render_error(conn, 404, "DID not registered: #{did}")

      {:valid, _} ->
        render_error(conn, 404, "DID has been revoked: #{did}")
    end
  end

  def render_error(conn, status_code, reason) do
    conn
    |> put_status(status_code)
    |> put_view(ErrorJSON)
    |> render("#{status_code}.json", detail: reason)
  end

  def format_did_document(did) do
    with %Operation{} = last <- DidServer.Log.get_last_op(did) do
      {:ok,
       last
       |> CryptoUtils.Did.to_plc_operation_data()
       |> Map.put("did", did)
       |> CryptoUtils.Did.format_did_plc_document()}
    else
      _ -> {:error, "DID not registered: #{did}"}
    end
  end
end
