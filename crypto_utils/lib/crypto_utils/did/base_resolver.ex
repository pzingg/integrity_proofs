defmodule CryptoUtils.Did.BaseResolver do
  @moduledoc """
  Dereferencing and resolving DIDs.
  """

  alias CryptoUtils.Did
  alias CryptoUtils.Did.{DereferencingMetadata, DocumentMetadata, ResolutionMetadata}

  defmodule DidURI do
    @moduledoc """
    - [DID](https://www.w3.org/TR/did-core/#did-syntax).
    - [DID path](https://www.w3.org/TR/did-core/#path). `path-abempty` component from
      [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    - [DID query](https://www.w3.org/TR/did-core/#query). `query` component from
      [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    - [DID fragment](https://www.w3.org/TR/did-core/#fragment). `fragment` component from
      [RFC 3986](https://www.rfc-editor.org/rfc/rfc3986#section-3.3).
    """
    defstruct [
      :did,
      :path,
      :query,
      :fragment
    ]

    def parse(url) when is_binary(url) do
      %URI{scheme: scheme, path: path, query: query, fragment: fragment} = URI.parse(url)

      if scheme == "did" do
        [method_and_id | rest] = String.split(path, "/", parts: 2)

        if String.contains?(method_and_id, ":") do
          did = "did:" <> method_and_id
          path = if is_nil(rest), do: nil, else: "/" <> hd(rest)
          {:ok, %__MODULE__{did: did, path: path, query: query, fragment: fragment}}
        else
          {:error, "No method specific id"}
        end
      else
        {:error, "Invalid scheme"}
      end
    end

    def to_string(%__MODULE__{did: did, path: path, query: query, fragment: fragment}) do
      path = path || ""
      query = if is_nil(query), do: "", else: "?#{query}"
      fragment = if is_nil(fragment), do: "", else: "##{fragment}"
      did <> path <> query <> fragment
    end
  end

  @doc """
  [Resolve a DID](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm) in a given
  representation.

  i.e. the `resolveRepresentation` function from
  - [DID Core](https://www.w3.org/TR/did-core/#did-resolution) and
  - [DID Resolution](https://w3c-ccg.github.io/did-resolution/#resolving)
  """
  def resolve_representation(resolver, did, input_metadata) do
    # Implement resolveRepresentation in terms of resolve.
    with {:ok, {res_meta, doc, doc_meta}} <- resolver.resolve(did, input_metadata),
         {:ok, doc_representation} <- Jason.encode(doc) do
      # Assume JSON-LD DID document
      {:ok,
       {%ResolutionMetadata{res_meta | content_type: "application/did+ld+json"},
        doc_representation, doc_meta}}
    else
      {:error, {%ResolutionMetadata{}, _, _} = reason} ->
        {:error, reason}

      {:error, json_error} ->
        {:error, {%ResolutionMetadata{error: json_error}, nil, %DocumentMetadata{}}}
    end
  end

  @doc """
  Dereference a DID URL, according to
  - [DID Core](https://www.w3.org/TR/did-core/#did-url-dereferencing) and
  - [DID Resolution](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm)
  """
  def dereference(resolver, did_url_str, did_url_dereferencing_input_metadata) do
    with {:ok, %DidURI{did: did, fragment: fragment} = did_uri} <-
           DidURI.parse(did_url_str),
         # 1
         did_res_input_metadata <-
           URI.decode_query(did_uri) |> CryptoUtils.to_keyword_list(),
         {:ok, {did_doc_res_meta, did_doc, did_doc_meta}} when is_binary(did_doc) <-
           resolver.resolve(did, did_res_input_metadata),
         # 2
         primary_did_uri <-
           %DidURI{did_uri | fragment: nil},
         {:ok, {deref_meta, content, content_meta}} <-
           dereference_primary_resource(
             resolver,
             primary_did_uri,
             did_url_dereferencing_input_metadata,
             did_doc_res_meta,
             did_doc,
             did_doc_meta
           ) do
      if is_nil(fragment) do
        {:ok, {deref_meta, content, content_meta}}
      else
        dereference_secondary_resource(
          resolver,
          primary_did_uri,
          fragment,
          did_url_dereferencing_input_metadata,
          deref_meta,
          content,
          content_meta
        )
      end
    else
      {:ok, {%ResolutionMetadata{}, _, _}} ->
        {:error, {%DereferencingMetadata{error: "notFound"}, nil, %DocumentMetadata{}}}

      {:error, {%ResolutionMetadata{error: error}, _, _}} ->
        {:error, {%DereferencingMetadata{error: error}, nil, %DocumentMetadata{}}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  [Dereferencing the Primary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary) - a subalgorithm of [DID URL dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm)
  """
  def dereference_primary_resource(
        resolver,
        %DidURI{path: path, query: query} = primary_did_uri,
        did_url_dereferencing_input_metadata,
        res_meta,
        did_doc,
        did_doc_meta
      ) do
    parameters = URI.decode_query(query) |> CryptoUtils.to_keyword_list([:service])
    service = Keyword.get(parameters, :service)

    cond do
      # 1
      !is_nil(service) ->
        dereference_primary_service(
          resolver,
          parameters,
          service,
          primary_did_uri,
          did_url_dereferencing_input_metadata,
          res_meta,
          did_doc,
          did_doc_meta
        )

      # 2
      is_nil(path) && is_nil(query) ->
        # 2.1
        # Add back contentType, since the resolve function does not include it, but we need
        # it to dereference the secondary resource.
        # TODO: detect non-JSON-LD DID documents
        {:ok,
         {%DereferencingMetadata{
            content_type: "application/did+ld+json",
            property_set: res_meta.property_set
          }, {:did_document, did_doc}, %DocumentMetadata{}}}

      # 3
      !is_nil(path) || !is_nil(query) ->
        # 3.1
        resolver.dereference(primary_did_uri, did_url_dereferencing_input_metadata)

      # 3.2
      # TODO: enable the client to dereference the DID URL

      # 4
      true ->
        # 4.1
        {:ok, {%DereferencingMetadata{}, nil, %DocumentMetadata{}}}
    end
  end

  def dereference_primary_service(
        _resolver,
        parameters,
        service,
        %DidURI{} = primary_did_uri,
        _did_url_dereferencing_input_metadata,
        _res_meta,
        did_doc,
        _did_doc_meta
      ) do
    # 1.1
    with {:service, service_object} when is_map(service_object) <-
           {:service, Did.select_service(did_doc, service)},
         # 1.2, 1.2.1
         # TODO: support these other cases?
         {:service_endpoint, input_service_endpoint_url}
         when is_binary(input_service_endpoint_url) <-
           {:service_endpoint, Map.get(service_object, "serviceEndpoint")},
         # 1.2.2, 1.2.3
         {:ok, output_service_endpoint_url} when is_binary(output_service_endpoint_url) <-
           construct_service_endpoint(primary_did_uri, parameters, input_service_endpoint_url) do
      # 1.3
      {:ok,
       {%DereferencingMetadata{content_type: "text/url"}, {:url, output_service_endpoint_url},
        %DocumentMetadata{}}}
    else
      {:service, _} -> error_result("Service not found")
      {:service_endpoint, nil} -> error_result("Missing service endpoint")
      {:service_endpoint, _} -> error_result("Service endpoint map or properties not supported")
    end
  end

  @doc """
  [Dereferencing the Secondary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary) - a subalgorithm of [DID URL dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm)
  """
  def dereference_secondary_resource(
        _resolver,
        primary_did_uri,
        fragment,
        _did_url_dereferencing_input_metadata,
        %DereferencingMetadata{content_type: content_type} = deref_meta,
        content,
        content_meta
      ) do
    # 1
    case content do
      {:did_document, doc} ->
        if content_type in ["application/did+json", "application/did+ld+json"] do
          # put the fragment back in the URL
          did_url = %DidURI{primary_did_uri | fragment: fragment} |> DidURI.to_string()
          # 1.1
          case Did.select_object(doc, did_url) do
            nil ->
              error_result("Unable to find object in DID document")

            object ->
              content_type =
                case content_type do
                  "application/did+json" -> "application/json"
                  "application/did+ld+json" -> "application/ld+json"
                end

              {:ok,
               {%DereferencingMetadata{content_type: content_type}, {:object, object},
                %DocumentMetadata{}}}
          end
        else
          error_result("Unsupported content type: #{content_type}")
        end

      {:url, url} ->
        # 2
        # 2.1
        if String.contains?(url, "#") do
          error_result(
            "DID URL and input service endpoint URL MUST NOT both have a fragment component"
          )
        else
          url = url <> "#" <> fragment
          {:ok, {deref_meta, {:url, url}, content_meta}}
        end

      _ ->
        # 3
        if is_nil(content_type) do
          error_result("Resource missing content type")
        else
          error_result("Unsupported content type: #{content_type}")
        end
    end
  end

  @doc """
  https://w3c-ccg.github.io/did-resolution/#service-endpoint-construction
  """
  def construct_service_endpoint(
        %DidURI{path: did_path, query: did_query, fragment: did_fragment},
        did_parameters,
        service_endpoint_url
      ) do
    # https://w3c-ccg.github.io/did-resolution/#algorithm
    # 1, 2, 3
    %URI{query: input_service_endpoint_query, fragment: input_service_endpoint_fragment} =
      URI.parse(service_endpoint_url)

    if !is_nil(did_fragment) && !is_nil(input_service_endpoint_fragment) do
      # https://w3c-ccg.github.io/did-resolution/#input
      {:error, "DID URL and input service endpoint URL MUST NOT both have a fragment component"}
    else
      # Work around https://github.com/w3c-ccg/did-resolution/issues/61
      relative_ref = Keyword.get(did_parameters, :relative_ref)
      {did_url_path, did_url_query} = relative_ref_parts(relative_ref, did_path, did_query)

      if did_url_path == :error do
        {did_url_path, did_url_query}
      else
        if !is_nil(did_url_query) && !is_nil(input_service_endpoint_query) do
          {:error, "DID URL and input service endpoint URL MUST NOT both have a query component"}
        else
          # 4, 5
          query = did_url_query || input_service_endpoint_query
          # 7, 8
          fragment = did_fragment || input_service_endpoint_fragment
          uri = URI.parse(service_endpoint_url)
          {:ok, %URI{uri | query: query, fragment: fragment} |> URI.to_string()}
        end
      end
    end
  end

  defp relative_ref_parts(ref, did_path, _) when is_binary(ref) do
    [ref_path | rest] = String.split(ref, "?", parts: 2)

    if !is_nil(did_path) do
      {:error, "DID URL and relativeRef MUST NOT both have a path component"}
    else
      ref_query = if is_nil(rest), do: nil, else: hd(rest)
      {ref_path, ref_query}
    end
  end

  defp relative_ref_parts(_, did_path, did_query) do
    # TODO: do something with the DID URL query that is being ignored in favor of the
    # relativeRef query
    {did_path, did_query}
  end

  defp error_result(reason) do
    {:error, %DereferencingMetadata{error: reason}, nil, %DocumentMetadata{}}
  end
end
