defmodule DidServerWeb.AccountsJSON do
  alias DidServer.Accounts.Account

  import Bitwise

  @context [
    "https://www.w3.org/ns/activitystreams",
    "https://w3id.org/security/v1",
    %{
      "manuallyApprovesFollowers" => "as:manuallyApprovesFollowers",
      "toot" => "http://joinmastodon.org/ns#",
      "featured" => %{
        "@id" => "toot:featured",
        "@type" => "@id"
      },
      "featuredTags" => %{
        "@id" => "toot:featuredTags",
        "@type" => "@id"
      },
      "alsoKnownAs" => %{
        "@id" => "as:alsoKnownAs",
        "@type" => "@id"
      },
      "movedTo" => %{
        "@id" => "as:movedTo",
        "@type" => "@id"
      },
      "schema" => "http://schema.org#",
      "PropertyValue" => "schema:PropertyValue",
      "value" => "schema:value",
      "IdentityProof" => "toot:IdentityProof",
      "discoverable" => "toot:discoverable",
      "Device" => "toot:Device",
      "Ed25519Signature" => "toot:Ed25519Signature",
      "Ed25519Key" => "toot:Ed25519Key",
      "Curve25519Key" => "toot:Curve25519Key",
      "EncryptedMessage" => "toot:EncryptedMessage",
      "publicKeyBase64" => "toot:publicKeyBase64",
      "deviceId" => "toot:deviceId",
      "claim" => %{
        "@type" => "@id",
        "@id" => "toot:claim"
      },
      "fingerprintKey" => %{
        "@type" => "@id",
        "@id" => "toot:fingerprintKey"
      },
      "identityKey" => %{
        "@type" => "@id",
        "@id" => "toot:identityKey"
      },
      "devices" => %{
        "@type" => "@id",
        "@id" => "toot:devices"
      },
      "messageFranking" => "toot:messageFranking",
      "messageType" => "toot:messageType",
      "cipherText" => "toot:cipherText",
      "suspended" => "toot:suspended",
      "Emoji" => "toot:Emoji",
      "focalPoint" => %{
        "@container" => "@list",
        "@id" => "toot:focalPoint"
      },
      "Hashtag" => "as:Hashtag"
    }
  ]

  def actor(%{
        user:
          %Account{
            username: username,
            domain: domain,
            display_name: display_name,
            description: description,
            avatar_mime_type: avatar_mime_type,
            banner_mime_type: banner_mime_type
          } = user
      }) do
    ap_id = Account.ap_id(user)
    published = NaiveDateTime.utc_now() |> CryptoUtils.format_datetime()

    public_key_pem =
      with {:ok, public_key} <- DidServer.Identities.get_public_key(user, :public_key),
           {:ok, pem} <- CryptoUtils.Keys.encode_pem_public_key(public_key) do
        pem
      else
        _ ->
          ""
      end

    # TODO alsoKnownAs in did document?
    aka =
      DidServer.Accounts.list_also_known_as_accounts(user)
      |> Enum.map(fn u -> Account.ap_id(u) end)
      |> Enum.filter(fn id -> id != ap_id end)
      |> Enum.sort()

    %{
      "@context" => @context,
      "id" => ap_id,
      "type" => "Person",
      "alsoKnownAs" => aka,
      "following" => ap_id <> "/following",
      "followers" => ap_id <> "/followers",
      "inbox" => ap_id <> "/inbox",
      "outbox" => ap_id <> "/outbox",
      "featured" => ap_id <> "/collections/featured",
      "featuredTags" => ap_id <> "/collections/tags",
      "preferredUsername" => username,
      "name" => display_name,
      "summary" => uni_encode(description),
      "url" => Account.ap_id(user, "@"),
      "manuallyApprovesFollowers" => false,
      "discoverable" => true,
      "published" => published <> "Z",
      "devices" => ap_id <> "/collections/devices",
      "publicKey" => %{
        "id" => ap_id <> "#main-key",
        "owner" => ap_id,
        "publicKeyPem" => public_key_pem
      },
      "tag" => [
        # "type" => "Emoji"
        # "type" => "Hashtag"
      ],
      "attachment" => [
        # "type" => "PropertyValue", "name" => "Twitter", etc.
      ],
      "endpoints" => %{
        "sharedInbox" => "https://#{domain}/inbox"
      },
      "icon" => %{
        "type" => "Image",
        "mediaType" => "image/jpeg",
        "url" => "https://#{domain}/accounts/avatars/#{username}.#{file_ext(avatar_mime_type)}"
      },
      "image" => %{
        "type" => "Image",
        "mediaType" => "image/jpeg",
        "url" => "https://#{domain}/accounts/banners/#{username}.#{file_ext(banner_mime_type)}"
      }
    }
  end

  def file_ext(_), do: "jpg"

  # "\u003cp\u003eNorthern California. \u003ca href=\"https://mastodon.cloud/tags/art\" class=\"mention hashtag\" rel=\"tag\"\u003e#\u003cspan\u003eart\u003c/span\u003e\u003c/a\u003e \u003ca href=\"https://mastodon.cloud/tags/languages\" class=\"mention hashtag\" rel=\"tag\"\u003e#\u003cspan\u003elanguages\u003c/span\u003e\u003c/a\u003e \u003ca href=\"https://mastodon.cloud/tags/architecture\" class=\"mention hashtag\" rel=\"tag\"\u003e#\u003cspan\u003earchitecture\u003c/span\u003e\u003c/a\u003e \u003ca href=\"https://mastodon.cloud/tags/cities\" class=\"mention hashtag\" rel=\"tag\"\u003e#\u003cspan\u003ecities\u003c/span\u003e\u003c/a\u003e \u003ca href=\"https://mastodon.cloud/tags/film\" class=\"mention hashtag\" rel=\"tag\"\u003e#\u003cspan\u003efilm\u003c/span\u003e\u003c/a\u003e \u003ca href=\"https://mastodon.cloud/tags/software\" class=\"mention hashtag\" rel=\"tag\"\u003e#\u003cspan\u003esoftware\u003c/span\u003e\u003c/a\u003e \u003ca href=\"https://mastodon.cloud/tags/savecaliforniascoast\" class=\"mention hashtag\" rel=\"tag\"\u003e#\u003cspan\u003esavecaliforniascoast\u003c/span\u003e\u003c/a\u003e\u003c/p\u003e"
  def uni_encode(string, predicate \\ &URI.char_unescaped?/1)

  def uni_encode(string, predicate)
      when is_binary(string) and is_function(predicate, 1) do
    for <<byte <- string>>, into: "", do: uni(byte, predicate)
  end

  def uni_encode(_, _), do: nil

  defp uni(char, predicate) do
    if predicate.(char) do
      <<char>>
    else
      <<"\\u00", hex(bsr(char, 4)), hex(band(char, 15))>>
    end
  end

  defp hex(n) when n <= 9, do: n + ?0
  defp hex(n), do: n + ?A - 10
end
