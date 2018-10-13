# Oauth2MetadataUpdater

> OAuth2 authorization server metadata updater for Elixir

Oauth2MetadataUpdater maintains an OAuth2 authorization server metadata up to date and performs the necessary validations.

Implements the following standards:
- [RFC8414](https://tools.ietf.org/html/rfc8414) - OAuth 2.0 Authorization Server Metadata
	- Except section 2.1 (Signed Authorization Server Metadata)
- [OpenID Connect Discovery 1.0 incorporating errata set 1](https://openid.net/specs/openid-connect-discovery-1_0.html)
	- Except section 2

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

  iex> Oauth2MetadataUpdater.get_jwks("https://accounts.google.com", suffix: "openid-configuration")
  {:ok,
   %{
     "keys" => [
       %{
         "alg" => "RS256",
         "e" => "AQAB",
         "kid" => "641fc053ef68a147d6e0845ab69b9d61aa4bc789",
         "kty" => "RSA",
         "n" => "svhYwK-oU1dhwKDpRZmpai4sDWtaROSEbWdyKMHTsc9nXoqCDWziX4DmCnaR8tMEuf2ZAmPVukcw3NdWRHVt_K2lPVsPwcZUtnGv1YkDpdwHj9-hbl_ao1SXaRflDZRhB2on9VUMRCky4M5fdHdIQhFccJ5yz8iHlnQ-R5hHKe8BWT6p6TXlRAFdFUaXR5nZvQvXZnvjdKAvvyCaeOfMxh5TFVuEqofTFVQjKrLTwqSSEQpv11lrkRzw1Y0x5NrRRCYjO2ywQpPBw_dQxnfnA5bQBIXR3mBtic218WXfyWWY9zJqqbzlQAJH-nPnime3mFFX3HfMgwTydMRGNAloiQ",
         "use" => "sig"
       },
       %{
         "alg" => "RS256",
         "e" => "AQAB",
         "kid" => "961cf60bcedd9067c4cf1f2ddf4ed612b536fb1a",
         "kty" => "RSA",
         "n" => "3DtaPxVC9Nd8pEn-Y50eyL5YxF-mT_zLXY_TummZNaczgX_XoXlFiK26FJZ2wf8CMrA4lul8otyEBtcI_sJUSDdw_ngWGNjA4XFnayO-GNwXG4pvfcILn4acO3YyiPdkb4PS6WYCGqVD5PIrnuCeKtX4K28vva8SUGCOiPiysNvoUpNGiqUxiBLWdvD9TJvrrC0QbpdGDPH2kzcHJjLQp3n0tCW6L06slFHufB9MBhlE0lN4egKlcaB4noqUitwv77WXBuWHTQRL431Bn7tzACL-xvvL6wgKqvLTT9FDaKvnEMDhomE1FPLKQEK-mAcNYQl_ro0BaQGPPlGSI76Y9Q",
         "use" => "sig"
       }
     ]
   }}
```
