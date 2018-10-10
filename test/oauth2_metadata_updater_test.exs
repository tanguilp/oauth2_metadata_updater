defmodule Oauth2MetadataUpdaterTest do
  use ExUnit.Case
  doctest Oauth2MetadataUpdater

  


  setup do
    bypass = Bypass.open(transport: :ssl)
    {:ok, bypass: bypass}
  end

  defp endpoint_url(bypass), do: "https://#{bypass.hostname}:#{bypass.port}"

  test "Parsing valid response and checking default values", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": [
         "code",
         "token",
         "id_token",
         "code token",
         "code id_token",
         "token id_token",
         "code token id_token",
         "none"
        ],
        "subject_types_supported": [
         "public"
        ],
        "id_token_signing_alg_values_supported": [
         "RS256"
        ],
        "scopes_supported": [
         "openid",
         "email",
         "profile"
        ],
        "token_endpoint_auth_methods_supported": [
         "client_secret_post",
         "client_secret_basic"
        ],
        "claims_supported": [
         "aud",
         "email",
         "email_verified",
         "exp",
         "family_name",
         "given_name",
         "iat",
         "iss",
         "locale",
         "name",
         "picture",
         "sub"
        ],
        "code_challenge_methods_supported": [
         "plain",
         "S256"
        ]})
      )
    end

    assert {:ok, "#{endpoint_url(bypass)}/auth"} ==
      Oauth2MetadataUpdater.get_claim(endpoint_url(bypass),
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end
end
