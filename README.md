# Oauth2MetadataUpdater

> OAuth2 and OpenID Connect metadata updater for Elixir

Oauth2MetadataUpdater maintains an OAuth2 or OpenID Connect server's metadata up to date and
performs the necessary validations. It also automatically adds the defaults values to
the response.

Implements the following standards:
- [RFC8414](https://tools.ietf.org/html/rfc8414) - OAuth 2.0 Authorization Server Metadata
  - Except section 2.1 (Signed Authorization Server Metadata)
- [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)
  - Except section 2

## Installation

```elixir
def deps do
  [
    {:oauth2_metadata_updater, "~> 1.0"}
  ]
end
```

## Usage

Oauth2MetadataUpdater dynamically loads metadata (lazy-loading) and keeps it in memory for further access. Examples:

```elixir

  iex> Oauth2MetadataUpdater.get_metadata_value("https://accounts.google.com", "authorization_endpoint", suffix: "openid-configuration")
  {:ok, "https://accounts.google.com/o/oauth2/v2/auth"}

  iex> Oauth2MetadataUpdater.get_metadata_value("https://login.live.com", "response_modes_supported", suffix: "openid-configuration")
  {:ok, ["query", "fragment", "form_post"]}

  iex> Oauth2MetadataUpdater.get_metadata_value("https://openid-connect.onelogin.com/oidc", "claims_supported", suffix: "openid-configuration", url_construction: :non_standard_append)
  {:ok,
   ["acr", "auth_time", "company", "custom_fields", "department", "email",
    "family_name", "given_name", "groups", "iss", "locale_code", "name",
    "phone_number", "preferred_username", "sub", "title", "updated_at"]}
```

## Options

- `suffix`: the well-know URI suffix as documented in the
[IANA registry](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml).
Defaults to `"openid-configuration"`
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
which standard to validate: `:oauth2` or `:oidc`. Defaults to `:oidc`

The `:suffix`, `:on_refresh_failure`, `:url_construction`, `:validation` options shall be used
unchanged for a given issuer between multiple calls, otherwise an exception will be raised.

## Loading JWK URIs

See [`JWKSURIUpdater`](https://github.com/tanguilp/jwks_uri_updater).
