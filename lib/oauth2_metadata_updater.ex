defmodule Oauth2MetadataUpdater do
  @moduledoc """
  Oauth2MetadataUpdater dynamically loads metadata (lazy-loading) and keeps it in memory for further access. Examples:

  It Implements the following standards:
  - [RFC8414](https://tools.ietf.org/html/rfc8414) - OAuth 2.0 Authorization Server Metadata
          - Except section 2.1 (Signed Authorization Server Metadata)
  - [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)
          - Except section 2

  The following functions accept the following options:
  - `suffix`: the well-know URI suffix as documented in the
  [IANA registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml).
  Defaults to `"oauth-authorization-server"`. Many issuers use `"openid-configuration"`
  - `refresh_interval`: the number of seconds to keep metadata in cache before it is fetched
  again. Defaults to `3600` seconds
  - `min_refresh_interval`: the delay before Oauth2MetadataUpdater will try to fetch metadata
  of an issuer again. It is intended to prevent fetching storms when the metadata is
  unavailable. Defaults to `10` seconds
  - `on_refresh_failure`: determines the behaviour of Oauth2MetadataUpdater when the issuer
  metadata *becomes* unavailable: `:keep_metadata` will keep the metadata in the cache,
  `:discard` will delete the metadata. Defaults to `:keep_metadata`
  - `:tesla_middlewares`: `Tesla` middlewares to add to the outgoing request
  - `url_construction`: `:standard` (default) or `:non_standard_append`. Given the issuer
  `"https://www.example.com/auth"` the result URI would be:
    - `:standard`: `"https://www.example.com/.well-known/oauth-authorization-server/auth"`
    - `:non_standard_append`:
    `"https://www.example.com/auth/.well-known/oauth-authorization-server"`
  - `validation`: in addition to the mandatory metadata values of the OAuth2 specification,
  OpenID Connect makes the `jwks_uri`, `subject_types_supported` and
  `id_token_signing_alg_values_supported` values mandatory. This option determines against
  which standard to validate: `:oauth2` or `:oidc`. Defaults to `:oauth2`

  The `:suffix`, `:on_refresh_failure`, `:url_construction`, `:validation` options shall be used
  unchanged for a given issuer between multiple calls, otherwise an exception will be raised.

  Note that OAuth2 and OpenID Connect default values are automatically added to the responses.
  """
  use Application

  @doc false

  def start(_type, _args) do
    import Supervisor.Spec

    children = [worker(Oauth2MetadataUpdater.Updater, [])]

    {:ok, _} =
      Supervisor.start_link(children, strategy: :one_for_one, name: :oauth2_metadata_updater_sup)
  end

  @doc """
  Returns `{:ok, value}` of the metadata of an issuer, or `{:error, error}` if it could not be
  retrieved or if validation failed.

  ## Examples
  ```elixir
  iex> Oauth2MetadataUpdater.get_metadata_value("https://accounts.google.com", "authorization_endpoint", suffix: "openid-configuration")
  {:ok, "https://accounts.google.com/o/oauth2/v2/auth"}

  iex> Oauth2MetadataUpdater.get_metadata_value("https://accounts.google.com", "token_endpoint", suffix: "openid-configuration")
  {:ok, "https://oauth2.googleapis.com/token"}

  iex> Oauth2MetadataUpdater.get_metadata_value("https://login.live.com", "response_modes_supported", suffix: "openid-configuration")
  {:ok, ["query", "fragment", "form_post"]}

  iex> Oauth2MetadataUpdater.get_metadata_value("https://login.live.com", "nonexisting_val", suffix: "openid-configuration")
  {:ok, nil}

  iex> Oauth2MetadataUpdater.get_metadata_value("https://openid-connect.onelogin.com/oidc", "claims_supported", suffix: "openid-configuration")
  {:error, :invalid_http_response_code}

  iex> Oauth2MetadataUpdater.get_metadata_value("https://openid-connect.onelogin.com/oidc", "claims_supported", suffix: "openid-configuration", url_construction: :non_standard_append)
  {:ok,
   ["acr", "auth_time", "company", "custom_fields", "department", "email",
    "family_name", "given_name", "groups", "iss", "locale_code", "name",
    "phone_number", "preferred_username", "sub", "title", "updated_at"]}
  ```
  """
  defdelegate get_metadata_value(issuer, claim, opts \\ []), to: Oauth2MetadataUpdater.Updater

  @doc """
  Returns `{:ok, map_of_all_values}` of the metadata of an issuer, or `{:error, error}` if it could not be
  retrieved or if validation failed.

  ## Example
  ```elixir
  iex> Oauth2MetadataUpdater.get_metadata("https://auth.login.yahoo.co.jp/yconnect/v2", suffix: "openid-configuration", url_construction: :non_standard_append)
    {:ok,
     %{
       "authorization_endpoint" => "https://auth.login.yahoo.co.jp/yconnect/v2/authorization",
       "claims_locales_supported" => ["ja-JP"],
       "claims_supported" => ["sub", "name", "given_name", "family_name", "email",
        "email_verified", "gender", "birthdate", "zoneinfo", "locale", "address",
        "iss", "aud", "exp", "iat", "nickname", "picture"],
       "display_values_supported" => ["page", "popup", "touch"],
       "grant_types_supported" => ["authorization_code", "implicit"],
       "id_token_signing_alg_values_supported" => ["RS256"],
       "issuer" => "https://auth.login.yahoo.co.jp/yconnect/v2",
       "jwks_uri" => "https://auth.login.yahoo.co.jp/yconnect/v2/jwks",
       "op_policy_uri" => "https://developer.yahoo.co.jp/yconnect/v2/guideline.html",
       "op_tos_uri" => "https://developer.yahoo.co.jp/yconnect/v2/guideline.html",
       "response_modes_supported" => ["query", "fragment"],
       "response_types_supported" => ["code", "token", "id_token", "code token",
        "code id_token", "token id_token", "code token id_token"],
       "revocation_endpoint_auth_methods_supported" => ["client_secret_basic"],
       "scopes_supported" => ["openid", "email", "profile", "address"],
       "service_documentation" => "https://developer.yahoo.co.jp/yconnect/",
       "subject_types_supported" => ["public"],
       "token_endpoint" => "https://auth.login.yahoo.co.jp/yconnect/v2/token",
       "token_endpoint_auth_methods_supported" => ["client_secret_post",
        "client_secret_basic"],
       "ui_locales_supported" => ["ja-JP"],
       "userinfo_endpoint" => "https://userinfo.yahooapis.jp/yconnect/v2/attribute"
     }}
  ```
  """
  defdelegate get_metadata(issuer, opts \\  []), to: Oauth2MetadataUpdater.Updater
end
