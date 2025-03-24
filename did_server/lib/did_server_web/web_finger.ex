defmodule DidServerWeb.WebFinger do
  @moduledoc """
  From Pleroma: A lightweight social networking server
  Copyright © 2017-2021 Pleroma Authors <https://pleroma.social/>
  SPDX-License-Identifier: AGPL-3.0-only
  """

  require Logger

  alias DidServer.Accounts
  alias DidServer.Accounts.Account
  alias DidServerWeb.XMLBuilder

  @accept_header_value_xml "application/xrd+xml"
  @accept_header_value_json "application/jrd+json"

  def host_meta do
    base_url = DidServerWeb.Endpoint.url()

    {
      :XRD,
      %{xmlns: "http://docs.oasis-open.org/ns/xri/xrd-1.0"},
      {
        :Link,
        %{
          rel: "lrdd",
          type: @accept_header_value_xml,
          template: "#{base_url}/.well-known/webfinger?resource={uri}"
        }
      }
    }
    |> XMLBuilder.to_doc()
  end

  def webfinger(resource, fmt) when is_binary(resource) and fmt in [:xml, :json] do
    case Accounts.get_account_by_identifier(resource) do
      %Account{} = user ->
        {:ok, represent_user(user, fmt)}

      _ ->
        {:error, "Account not found"}
    end
  end

  defp gather_links(%Account{} = user) do
    [
      %{
        "rel" => "self",
        "type" => "application/activity+json",
        "href" => Account.ap_id(user, "users/")
      }
      # %{
      #  "rel" => "http://webfinger.net/rel/profile-page",
      #  "type" => "text/html",
      #  "href" => Account.ap_id(user, "users/")
      # }
    ]
  end

  defp gather_aliases(%Account{} = user) do
    Accounts.list_also_known_as_accounts(user)
    |> Enum.filter(fn alias -> alias.id != user.id end)
    |> Enum.map(fn alias -> Account.ap_id(alias, "users/") end)
  end

  def represent_user(%Account{} = user, :json) do
    %{
      "subject" => Account.ap_acct(user, "acct:"),
      "aliases" => gather_aliases(user),
      "links" => gather_links(user)
    }
  end

  def represent_user(%Account{} = user, :xml) do
    aliases =
      user
      |> gather_aliases()
      |> Enum.map(&{:Alias, &1})

    links =
      gather_links(user)
      |> Enum.map(fn link -> {:Link, link} end)

    {
      :XRD,
      %{xmlns: "http://docs.oasis-open.org/ns/xri/xrd-1.0"},
      [
        {:Subject, Account.ap_acct(user, "acct:")}
      ] ++ aliases ++ links
    }
    |> XMLBuilder.to_doc()
  end

  defp webfinger_from_xml(body) do
    with {:ok, doc} <- parse_document(body) do
      subject = string_from_xpath("//Subject", doc)

      subscribe_address =
        ~s{//Link[@rel="http://ostatus.org/schema/1.0/subscribe"]/@template}
        |> string_from_xpath(doc)

      ap_id =
        ~s{//Link[@rel="self" and @type="application/activity+json"]/@href}
        |> string_from_xpath(doc)

      data = %{
        "subject" => subject,
        "subscribe_address" => subscribe_address,
        "ap_id" => ap_id
      }

      {:ok, data}
    end
  end

  defp webfinger_from_json(body) do
    with {:ok, doc} <- Jason.decode(body) do
      data =
        Enum.reduce(doc["links"], %{"subject" => doc["subject"]}, fn link, data ->
          case {link["type"], link["rel"]} do
            {"application/activity+json", "self"} ->
              Map.put(data, "ap_id", link["href"])

            {"application/ld+json; profile=\"https://www.w3.org/ns/activitystreams\"", "self"} ->
              Map.put(data, "ap_id", link["href"])

            {nil, "http://ostatus.org/schema/1.0/subscribe"} ->
              Map.put(data, "subscribe_address", link["template"])

            _ ->
              Logger.error("Unhandled type: #{inspect(link["type"])}")
              data
          end
        end)

      {:ok, data}
    end
  end

  def get_template_from_xml(body) do
    xpath = "//Link[@rel='lrdd']/@template"

    with {:ok, doc} <- parse_document(body),
         template when template != nil <- string_from_xpath(xpath, doc) do
      {:ok, template}
    end
  end

  def find_lrdd_template(domain) do
    # WebFinger is restricted to HTTPS - https://tools.ietf.org/html/rfc7033#section-9.1
    meta_url = "https://#{domain}/.well-known/host-meta"
    opts = [headers: %{"accept" => "application/json"}]

    with {:ok, body, _headers} <- CryptoUtils.HttpClient.fetch(meta_url, opts) do
      get_template_from_xml(body)
    else
      {:error, message, _status_code} ->
        Logger.warning("Can't find LRDD template in #{inspect(meta_url)}: #{message}")
        {:error, :lrdd_not_found}
    end
  end

  defp get_address_from_domain(domain, encoded_account) when is_binary(domain) do
    case find_lrdd_template(domain) do
      {:ok, template} ->
        String.replace(template, "{uri}", encoded_account)

      _ ->
        "https://#{domain}/.well-known/webfinger?resource=#{encoded_account}"
    end
  end

  defp get_address_from_domain(_, _), do: {:error, :webfinger_no_domain}

  def finger(%URI{host: domain} = account) do
    if CryptoUtils.http_uri?(account) do
      finger(URI.to_string(account), domain)
    else
      {:error, "WebFinger: account is not an HTTP URL"}
    end
  end

  def finger(account) when is_binary(account) do
    account = String.trim_leading(account, "@")

    with [_name, domain] <- String.split(account, "@") do
      finger(account, domain)
    else
      _ ->
        {:error, "WebFinger: account is not an '@' address"}
    end
  end

  def finger(account, domain) do
    encoded_account = URI.encode("acct:#{account}")
    address = get_address_from_domain(domain, encoded_account)
    opts = [headers: %{"accept" => "#{@accept_header_value_xml}, #{@accept_header_value_json}"}]

    with {:ok, body, headers} <-
           CryptoUtils.HttpClient.fetch(address, opts) do
      case List.keyfind(headers, "content-type", 0) do
        {_, content_type} ->
          case Plug.Conn.Utils.media_type(content_type) do
            {:ok, "application", subtype, _} when subtype in ~w(xrd+xml xml) ->
              webfinger_from_xml(body)

            {:ok, "application", subtype, _} when subtype in ~w(jrd+json json) ->
              webfinger_from_json(body)

            _ ->
              {:error, {:content_type, content_type}}
          end

        _ ->
          {:error, {:content_type, nil}}
      end
    else
      {:error, reason, _status_code} ->
        Logger.error("Couldn't finger #{account}: #{reason}")
        {:error, reason}
    end
  end

  def string_from_xpath(_, :error), do: nil

  def string_from_xpath(xpath, doc) do
    try do
      {:xmlObj, :string, res} = :xmerl_xpath.string(~c"string(#{xpath})", doc)

      res =
        res
        |> to_string
        |> String.trim()

      if res == "", do: nil, else: res
    catch
      _e ->
        Logger.error("Couldn't find xpath #{xpath} in XML doc")
        nil
    end
  end

  def parse_document(text) do
    try do
      {doc, _rest} =
        text
        |> :binary.bin_to_list()
        |> :xmerl_scan.string(quiet: true)

      {:ok, doc}
    rescue
      _e ->
        Logger.error("Couldn't parse XML: #{text}")
        :error
    catch
      :exit, _error ->
        Logger.error("Couldn't parse XML: #{text}")
        :error
    end
  end
end
