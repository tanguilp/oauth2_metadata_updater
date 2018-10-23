defmodule Oauth2MetadataUpdaterTest do
  use ExUnit.Case

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
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:ok, "#{endpoint_url(bypass)}/auth"} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
    assert {:ok, ["openid", "email", "profile"]} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "scopes_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Fail when no issuer in response", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :invalid_issuer_value} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Issuer in response must be the same as the requested one", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "https://example.net/connect",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :invalid_issuer_value} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Issuer in response must be the same as the requested one - not taking into account unicode normalization (test with noël strings)", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", URI.encode("/.well-known/oauth-authorization-server/noël"), fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}/noël",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :invalid_issuer_value} ==
      Oauth2MetadataUpdater.get_metadata_value(URI.encode(endpoint_url(bypass) <> "/noël"),
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  # such issuers should be detected early enough so that no HTTP request will actually be made
  test "Non-HTTPS issuers are rejected", %{bypass: bypass} do
    assert {:error, :invalid_uri_scheme} ==
      Oauth2MetadataUpdater.get_metadata_value("http://#{bypass.hostname}:#{bypass.port}",
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Rejecting issuers with query parameters", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}?queryparam=queryvalue",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :invalid_issuer_value} ==
      Oauth2MetadataUpdater.get_metadata_value("https://#{bypass.hostname}:#{bypass.port}",
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end


  test "Rejecting issuers with fragment", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}#framentvalue",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :invalid_issuer_value} ==
      Oauth2MetadataUpdater.get_metadata_value("https://#{bypass.hostname}:#{bypass.port}",
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "The well-known suffix must be registered at the IANA registry", %{bypass: bypass} do

    assert {:error, :invalid_suffix} ==
      Oauth2MetadataUpdater.get_metadata_value("https://#{bypass.hostname}:#{bypass.port}",
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      suffix: "unregistered-suffix",
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Response content type must be application/json", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/xml")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :invalid_response_content_type} ==
      Oauth2MetadataUpdater.get_metadata_value("https://#{bypass.hostname}:#{bypass.port}",
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Response status must be 200", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(400, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :invalid_http_response_code} ==
      Oauth2MetadataUpdater.get_metadata_value("https://#{bypass.hostname}:#{bypass.port}",
                                      "authorization_endpoint",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "authorization_endpoint is mandatory unless no grant type uses it", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "grant_types_supported": ["password", "client_credentials", "refresh_token", "authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :missing_authorization_endpoint} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "jwks_uri",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "authorization_endpoint not necessary when no grant type uses it", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "grant_types_supported": ["password", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:ok, _} =
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "jwks_uri",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Token endpoint required when grant types other than implicit", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "grant_types_supported": ["password", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :missing_token_endpoint} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "jwks_uri",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Token endpoint not required when only implicit grant type is supported", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "grant_types_supported": ["implicit"],
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:ok, _} =
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "jwks_uri",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "JWKS URI must be HTTPS", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "grant_types_supported": ["implicit"],
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "http://example.com/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :jwks_invalid_uri_scheme} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "jwks_uri",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end


  test "response_types_supported is mandatory", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "grant_types_supported": ["implicit"],
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :missing_response_types_supported} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "jwks_uri",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end


  test "Defaut for response_modes_supported is [\"query\", \"fragment\"]", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "grant_types_supported": ["implicit"],
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:ok, ["query", "fragment"]} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "response_modes_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Defaut for grant_types_supported is [\"authorization_code\", \"implicit\"]", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:ok, ["authorization_code", "implicit"]} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "grant_types_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "Defaut for token_endpoint_auth_methods_supported is [\"client_secret_basic\"]", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:ok, ["client_secret_basic"]} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "token_endpoint_auth_methods_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "token_endpoint_auth_signing_alg_values_supported mandatory if private_key_jwt or client_secret_jwt used", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :missing_token_endpoint_auth_signing_alg_values_supported} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "token_endpoint_auth_signing_alg_values_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "token_endpoint_auth_signing_alg_values_supported shall not use value `none`", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
        "token_endpoint_auth_signing_alg_values_supported": ["RS256", "none"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :none_value_forbidden_token_endpoint_auth_signing_values_supported} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "token_endpoint_auth_signing_alg_values_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "revocation_endpoint_auth_methods_supported default value should be `client_secret_basic`", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:ok, ["client_secret_basic"]} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "revocation_endpoint_auth_methods_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "revocation_endpoint_auth_signing_alg_values_supported mandatory if private_key_jwt or client_secret_jwt used", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_jwt", "client_secret_basic"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :missing_revocation_endpoint_auth_signing_alg_values_supported} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "revocation_endpoint_auth_methods_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "revocation_endpoint_auth_signing_alg_values_supported shall not use value `none`", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "revocation_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
        "revocation_endpoint_auth_signing_alg_values_supported": ["RS256", "none"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :none_value_forbidden_revocation_endpoint_auth_signing_alg_values_supported} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "revocation_endpoint_auth_methods_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "introspection_endpoint_auth_signing_alg_values_supported mandatory if private_key_jwt or client_secret_jwt used", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_jwt", "client_secret_basic"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :missing_introspection_endpoint_auth_signing_alg_values_supported} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "introspection_endpoint_auth_methods_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end

  test "introspection_endpoint_auth_signing_alg_values_supported shall not use value `none`", %{bypass: bypass} do
    Bypass.expect_once bypass, "GET", "/.well-known/oauth-authorization-server", fn conn ->
      Plug.Conn.put_resp_header(conn, "Content-Type", "application/json")
      |> Plug.Conn.resp(200, ~s({
        "issuer": "#{endpoint_url(bypass)}",
        "authorization_endpoint": "#{endpoint_url(bypass)}/auth",
        "token_endpoint": "#{endpoint_url(bypass)}/token",
        "userinfo_endpoint": "#{endpoint_url(bypass)}/userinfo",
        "revocation_endpoint": "#{endpoint_url(bypass)}/revoke",
        "jwks_uri": "#{endpoint_url(bypass)}/certs",
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
        "introspection_endpoint_auth_methods_supported": ["client_secret_post", "private_key_jwt", "client_secret_basic"],
        "introspection_endpoint_auth_signing_alg_values_supported": ["RS256", "none"],
        "scopes_supported": ["openid", "email", "profile"],
        "code_challenge_methods_supported": ["plain", "S256"]})
      )
    end

    assert {:error, :none_value_forbidden_introspection_endpoint_auth_signing_alg_values_supported} ==
      Oauth2MetadataUpdater.get_metadata_value(endpoint_url(bypass),
                                      "introspection_endpoint_auth_methods_supported",
                                      resolve_jwks: false,
                                      ssl: [cacerts: [bypass.ssl_cert]])
  end
end
