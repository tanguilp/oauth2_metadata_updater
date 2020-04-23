defmodule Oauth2MetadataUpdaterTest do
  use ExUnit.Case

  import Oauth2MetadataUpdater

  @metadata %{
    "issuer" => "https://example.com",
    "authorization_endpoint" => "https://example.com/auth",
    "token_endpoint" => "https://example.com/token",
    "userinfo_endpoint" => "https://example.com/userinfo",
    "revocation_endpoint" => "https://example.com/revoke",
    "jwks_uri" => "https://example.com/certs",
    "response_types_supported" => ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
    "scopes_supported" => ["openid", "email", "profile"],
    "code_challenge_methods_supported" => ["plain", "S256"]
  }

  @hdrs [{"content-type", "application/json"}]

  setup_all do
    Tesla.Mock.mock_global(fn
      %{method: :get, url: "https://example.com/.well-known/oauth-authorization-server"} ->
        %Tesla.Env{status: 200, body: @metadata, headers: @hdrs}

      %{method: :get, url: "https://noissuer.example.com/.well-known/oauth-authorization-server"} ->
        %Tesla.Env{status: 200, body: Map.delete(@metadata, "issuer"), headers: @hdrs}

      %{method: :get, url: "https://invalidissuer.example.com/.well-known/oauth-authorization-server"} ->
        %Tesla.Env{status: 200, body: Map.put(@metadata, "issuer", "https://other.issuer.com"), headers: @hdrs}

      %{method: :get, url: "https://example.com/.well-known/oauth-authorization-server/noël"} ->
        %Tesla.Env{status: 200, body: Map.put(@metadata, "issuer", "https://example.com/noël"), headers: @hdrs}

      %{method: :get, url: "https://issuerwithqueryparams.example.com/.well-known/oauth-authorization-server"} ->
        %Tesla.Env{status: 200, body: Map.put(@metadata, "issuer", "https://example.com?a=b"), headers: @hdrs}

      %{method: :get, url: "https://issuerwithfragment.example.com/.well-known/oauth-authorization-server"} ->
        %Tesla.Env{status: 200, body: Map.put(@metadata, "issuer", "https://example.com#frag"), headers: @hdrs}

      %{method: :get, url: "https://invalidcontenttype.example.com/.well-known/oauth-authorization-server"} ->
        %Tesla.Env{status: 200, body: @metadata}

      %{method: :get, url: "https://invalidstatuscode.example.com/.well-known/oauth-authorization-server"} ->
        %Tesla.Env{status: 201, body: @metadata, headers: @hdrs}

      %{method: :get, url: "https://missingazendpoint.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://missingazendpoint.example.com")
          |> Map.delete("authorization_endpoint")

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://missingazendpointok.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://missingazendpointok.example.com")
          |> Map.put("grant_types_supported", ["password", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"])
          |> Map.delete("authorization_endpoint")

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://missingtokenendpoint.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://missingtokenendpoint.example.com")
          |> Map.delete("token_endpoint")

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://missingtokenendpointok.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://missingtokenendpointok.example.com")
          |> Map.put("grant_types_supported", ["implicit"])
          |> Map.delete("token_endpoint")

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://invalidjwksuri.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://invalidjwksuri.example.com")
          |> Map.put("jwks_uri", "http://example.com/keys")

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://missingresponsetype.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://missingresponsetype.example.com")
          |> Map.delete("response_types_supported")

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://clientsecretjwt.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://clientsecretjwt.example.com")
          |> Map.put("token_endpoint_auth_methods_supported", ["client_secret_jwt"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://privatekeyjwt.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://privatekeyjwt.example.com")
          |> Map.put("token_endpoint_auth_methods_supported", ["private_key_jwt"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://tokenendpointnonealg.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://tokenendpointnonealg.example.com")
          |> Map.put("token_endpoint_auth_methods_supported", ["private_key_jwt"])
          |> Map.put("token_endpoint_auth_signing_alg_values_supported", ["RS256", "none", "ES256"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://clientsecretjwtrevoc.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://clientsecretjwtrevoc.example.com")
          |> Map.put("revocation_endpoint_auth_methods_supported", ["client_secret_jwt"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://privatekeyjwtrevoc.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://privatekeyjwtrevoc.example.com")
          |> Map.put("revocation_endpoint_auth_methods_supported", ["private_key_jwt"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://revocendpointnonealg.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://revocendpointnonealg.example.com")
          |> Map.put("revocation_endpoint_auth_methods_supported", ["private_key_jwt"])
          |> Map.put("revocation_endpoint_auth_signing_alg_values_supported", ["RS256", "none", "ES256"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://clientsecretjwtintro.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://clientsecretjwtintro.example.com")
          |> Map.put("introspection_endpoint_auth_methods_supported", ["client_secret_jwt"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://privatekeyjwtintro.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://privatekeyjwtintro.example.com")
          |> Map.put("introspection_endpoint_auth_methods_supported", ["private_key_jwt"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}

      %{method: :get, url: "https://introendpointnonealg.example.com/.well-known/oauth-authorization-server"} ->
        metadata =
          @metadata
          |> Map.put("issuer", "https://introendpointnonealg.example.com")
          |> Map.put("introspection_endpoint_auth_methods_supported", ["private_key_jwt"])
          |> Map.put("introspection_endpoint_auth_signing_alg_values_supported", ["RS256", "none", "ES256"])

        %Tesla.Env{status: 200, body: metadata, headers: @hdrs}
    end)

    :ok
  end

  test "Parsing valid response and checking default values" do
    assert {:ok, metadata} = get_metadata("https://example.com")
    assert Enum.sort(metadata["grant_types_supported"]) == ["authorization_code", "implicit"]
    assert Enum.sort(metadata["response_modes_supported"]) == ["fragment", "query"]
    assert metadata["token_endpoint_auth_methods_supported"] == ["client_secret_basic"]
    assert metadata["revocation_endpoint_auth_methods_supported"] == ["client_secret_basic"]
  end

  test "Fail when no issuer in response" do
    assert {:error, _} = get_metadata("https://noissuer.example.com")
  end

  test "Issuer in response must be the same as the requested one" do
    assert {:error, _} = get_metadata("https://invalidissuer.example.com")
  end

  test "Issuer in response must be the same as the requested one - not taking into account unicode normalization (test with noël strings)" do
    assert {:error, _} = get_metadata("https://example.com/noël")
  end

  ## such issuers should be detected early enough so that no HTTP request will actually be made
  test "Non-HTTPS issuers are rejected" do
    assert {:error, _} = get_metadata("http://example.com/noël")
  end

  test "Rejecting issuers with query parameters" do
    assert {:error, _} = get_metadata("https://issuerwithqueryparams.example.com")
  end

  test "Rejecting issuers with fragment" do
    assert {:error, _} = get_metadata("https://issuerwithfragment.example.com")
  end

  #test "The well-known suffix must be registered at the IANA registry" do
  #  assert {:error, _} = get_metadata("https://example.com", suffix: "unregistered-suffix")
  #end

  test "Response content type must be application/json" do
    assert {:error, :invalid_response_content_type} == get_metadata("https://invalidcontenttype.example.com")
  end

  test "Response status must be 200" do
    assert {:error, :invalid_http_response_code} == get_metadata("https://invalidstatuscode.example.com")
  end

  test "authorization_endpoint is mandatory unless no grant type uses it" do
    assert {:error, :missing_authorization_endpoint} == get_metadata("https://missingazendpoint.example.com")
  end

  test "authorization_endpoint not necessary when no grant type uses it" do
    assert {:ok, _} = get_metadata("https://missingazendpointok.example.com")
  end

  test "Token endpoint required when grant types other than implicit" do
    assert {:error, :missing_token_endpoint} == get_metadata("https://missingtokenendpoint.example.com")
  end

  test "Token endpoint not required when only implicit grant type is supported" do
    assert {:ok, _} = get_metadata("https://missingtokenendpointok.example.com")
  end

  test "JWKS URI must be HTTPS" do
    assert {:error, :jwks_invalid_uri_scheme} == get_metadata("https://invalidjwksuri.example.com")
  end


  test "response_types_supported is mandatory" do
    assert {:error, :missing_response_types_supported} == get_metadata("https://missingresponsetype.example.com")
  end

  test "token_endpoint_auth_signing_alg_values_supported mandatory if private_key_jwt or client_secret_jwt used" do
    assert {:error, :missing_token_endpoint_auth_signing_alg_values_supported} == get_metadata("https://clientsecretjwt.example.com")
    assert {:error, :missing_token_endpoint_auth_signing_alg_values_supported} == get_metadata("https://privatekeyjwt.example.com")
  end

  test "token_endpoint_auth_signing_alg_values_supported shall not use value `none`" do
    assert {:error, :none_value_forbidden_token_endpoint_auth_signing_values_supported} == get_metadata("https://tokenendpointnonealg.example.com")
  end

  test "revocation_endpoint_auth_signing_alg_values_supported mandatory if private_key_jwt or client_secret_jwt used" do
    assert {:error, :missing_revocation_endpoint_auth_signing_alg_values_supported} == get_metadata("https://clientsecretjwtrevoc.example.com")
    assert {:error, :missing_revocation_endpoint_auth_signing_alg_values_supported} == get_metadata("https://privatekeyjwtrevoc.example.com")
  end

  test "revocation_endpoint_auth_signing_alg_values_supported shall not use value `none`" do
    assert {:error, :none_value_forbidden_revocation_endpoint_auth_signing_alg_values_supported} == get_metadata("https://revocendpointnonealg.example.com")
  end

  test "introspection mandatory if private_key_jwt or client_secret_jwt used" do
    assert {:error, :missing_introspection_endpoint_auth_signing_alg_values_supported} == get_metadata("https://clientsecretjwtintro.example.com")
    assert {:error, :missing_introspection_endpoint_auth_signing_alg_values_supported} == get_metadata("https://privatekeyjwtintro.example.com")
  end

  test "introspection shall not use value `none`" do
    assert {:error, :none_value_forbidden_introspection_endpoint_auth_signing_alg_values_supported} == get_metadata("https://introendpointnonealg.example.com")
  end
end
