# Oauth2MetadataUpdater

> OAuth2 authorization server metadata updater for Elixir

Oauth2MetadataUpdater maintains OAuth2 AS metadata up to date in accordance to the following specification: https://www.ietf.org/id/draft-ietf-oauth-discovery-07.txt

## Installation

First, add Oauth2MetadataUpdater to your `mix.exs` dependencies:

```elixir
def deps do
  [
    {:oauth2_metadata_updater, "~> 0.1.0"}
  ]
end
```

then run `$ mix deps.get`

## Configuration

Configure OAuth2 issuers in your `config.exs` file:
```elixir
config :oauth2_metadata_updater,
  issuers:
  %{
    "https://accounts.google.com" => [forced_refresh_min_interval: 5],
    "https://login.salesforce.com" => [],
    "https://login.windows.net/common" => [],
    "https://auth.globus.org" => [refresh_interval: 60*12, resolve_jwks: false],
    "https://auth.login.yahoo.co.jp/yconnect/v2" => []
  }
```
Each issuer (which is the the authorization server's issuer identifier) can be
configured with the following options:
* `refresh_interval`: after initial update, delay after which metadata will be refreshed
(in seconds). Defaults to `3600` (1 hour)
* `well_known_path`: well known path where to find the OAuth2 AS metadata. Defaults to `"/.well-known/openid-configuration"`
* `resolve_jwks`: if the `jwks_uri` is returned in the metadata, determines whether jwks URI
automatically resolved. Defaults to `true`
* `forced_refresh_min_interval`: determines minimum delay for metadata update of the issuer
in seconds, to be used as a basic throttling mechanism when force-updating. Defaults to `30`

## Usage

When Oauth2MetadataUpdater starts, it automatically resolves OAuth2 metadata of the configured
issuers The metadata values can be accessed individually:

```elixir
iex> Oauth2MetadataUpdater.get_claim("https://login.salesforce.com", "authorization_endpoint")
"https://login.salesforce.com/services/oauth2/authorize"

iex> Oauth2MetadataUpdater.get_claim("https://login.salesforce.com", "response_types_supported")
["code", "token", "token id_token"]

iex> Oauth2MetadataUpdater.get_claim("https://auth.login.yahoo.co.jp/yconnect/v2", "response_types_supported")
["code", "token", "id_token", "code token", "code id_token", "token id_token",
   "code token id_token"]

iex> Oauth2MetadataUpdater.get_claim("https://auth.login.yahoo.co.jp/yconnect/v2", "revocation_endpoint")
nil

iex> Oauth2MetadataUpdater.get_claim("https://auth.globus.org", "revocation_endpoint")
"https://auth.globus.org/v2/oauth2/token/revoke"
```

or as a whole:
```elixir
iex> Oauth2MetadataUpdater.get_all_claims("https://login.salesforce.com")
%{"authorization_endpoint" => "https://login.salesforce.com/services/oauth2/authorize",
  "claims_supported" => ["active", "address", "email", "email_verified",
  "family_name", "given_name", "is_app_installed", "language", "locale",
  "name", "nickname", "organization_id", "phone_number",
  "phone_number_verified", "photos", "picture", "preferred_username",
  "profile", "sub", "updated_at", "urls", "user_id", "user_type", "zoneinfo"],
  "display_values_supported" => ["page", "popup", "touch"],
  "id_token_signing_alg_values_supported" => ["RS256"],
  "issuer" => "https://login.salesforce.com",
  "jwks_uri" => "https://login.salesforce.com/id/keys",
  "response_types_supported" => ["code", "token", "token id_token"],
  "revocation_endpoint" => "https://login.salesforce.com/services/oauth2/revoke",
  "scopes_supported" => ["id", "api", "web", "full", "chatter_api",
  "visualforce", "refresh_token", "openid", "profile", "email", "address",
  "phone", "offline_access", "custom_permissions", "wave_api", "eclair_api"],
  "subject_types_supported" => ["public"],
  "token_endpoint" => "https://login.salesforce.com/services/oauth2/token",
  "token_endpoint_auth_methods_supported" => ["client_secret_post",
  "private_key_jwt"],
  "userinfo_endpoint" => "https://login.salesforce.com/services/oauth2/userinfo"}
```

Jwks can be accessed the same way:
```elixir
iex> Oauth2MetadataUpdater.get_jwks("https://accounts.google.com")
%{"keys" => [%{"alg" => "RS256", "e" => "AQAB",
       "kid" => "b3b9177bc89466baacf57d1c06e1d265f77d5ac1", "kty" => "RSA",
       "n" => "rFNqrzuAQzohqTUiAaRrFRUfYZj9mrDM4sgt5IJdcq2tn-bQOt5Fs61IXrSQiev5nD_Y56lebBdHvCa8oOpkyLM6pBT3AgPr71fZrkRH5YJObXtc929iAcXIzDR-uyUyzf_RZEb9R3pz64XJrPRz-2zynteqo8M56M3rOLxW-t4wukv1FQhV63N6eyyTJmMfsI_QKt3p2Ttj3VoQt8ew14xdANWx8Gf5Wvb7zqznHL3k2y9C75dG0zlHmm8x_PkESY8eACszMUyhYyDBpqAo9IQxgDrdlwm0B5N7B66VjNQglKyyVqqnbmtBRSURMBJQDBdBl8pdnSE5Hb2ozhBcNQ",
       "use" => "sig"},
     %{"alg" => "RS256", "e" => "AQAB",
       "kid" => "4d0f3e422508f8ad1b61b46dd63e26ccbe163391", "kty" => "RSA",
       "n" => "4OlGpghOtSl03RaOtY-82l98rCQ2eyWYhQBzHOt6yOBpdWbRgniJF9cQ3gKwI-OjNbXNLOTafsoj2qeZMS6goZsLvnOpagR_ZF7EM4fiy8iYwt7jvQBXVtl_qnJuJzkdt3tBue_YcikFDJe0SqzlxAqt8CQ3csXXs8KRs0mrlCon-SfGJMPoxOnFo-IPrPM5Vr8lgQd2VvHMjmnX2duS0ctlXilYNdZAUy2OKV1xB08ZJgGOnuUbf8FGX071U6am0rXkfazLNwAYzKF8SpCPGVjVSqZAuh3GkdbHHh5qDXuY7HwgZTsN6h39mzJBfVuO59zbS0G5shP2QgvIXm_kyw",
       "use" => "sig"},
     %{"alg" => "RS256", "e" => "AQAB",
       "kid" => "c95b9d128b9f9845b57b661f9da84f349b841520", "kty" => "RSA",
       "n" => "xWSU2UgJB7_Qg0lDyn6YahWbSnBAIEjm7C-FwmUhd8EsuOSaJh__oTZY8v3l92B1bmVlLsJlbu7VajJ-mz8_fnwUPCdTfZs00jL2Rcmcip1o0oEu8gt93EOnNvsNXaaiuMwKfC1_v78OBKZRZJu3h27tKbpKxeoPac2Ofyt4E1q6yGAn4iDjsh01e-GaCUydfmt3YObrPvluPZCLPJSihFugsbby0TqjznetCmEFKrId2UKvq1i5IdWRmvlzZxnw0CQXDpKua8DPuZDTnx9sP8662daYj6ydVADshRQuqFNspax2QelocbU01HEUze1FmbNZ7JmzdWQL2f79dMr0dQ",
       "use" => "sig"}]}
iex> Oauth2MetadataUpdater.get_jwks("https://auth.globus.org")
nil
```

Refresh of metadata can be forced in a *synchronous* manner:
```elixir
iex> Oauth2MetadataUpdater.update_metadata("https://accounts.google.com")
{:ok, :updated}

iex> Oauth2MetadataUpdater.update_metadata("https://accounts.google.com")
{:ok, :not_updated}
```
The `Oauth2MetadataUpdater.update_metadata/1` function returns `{:ok, :updated}` if the issuer
metadata has not been refresh for `forced_refresh_min_interval` seconds, `{:ok, :not_updated}`
otherwise.

