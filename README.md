# Oauth2MetadataUpdater

> OAuth2 authorization server metadata updater for Elixir

Oauth2MetadataUpdater maintains an OAuth2 authorization server metadata up to date and performs the necessary validations.

Implements the following standards:
- [RFC8414](https://tools.ietf.org/html/rfc8414) - OAuth 2.0 Authorization Server Metadata
	- Except section 2.1 (Signed Authorization Server Metadata)
- [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)
	- Except section 2

## Installation

```elixir
def deps do
  [
    {:oauth2_metadata_updater, github: "tanguilp/oauth2_metadata_updater", tag: "v0.2.0"}
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

## Version 0.2.0

Starting with version 0.2.0, `Oauth2MetadataUpdater` doesn't load jwk URIs anymore. One can use
[JWKSURIUpdater](https://github.com/tanguilp/jwks_uri_updater) instead.
