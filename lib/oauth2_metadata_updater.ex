defmodule Oauth2MetadataUpdater do
  @moduledoc """
  Keeps OAuth2 / OpenID Connect metadata up to date

  This module periodically updates OAuth2 metadata (OAuth 2.0 Authorization Server Metadata
  draft-ietf-oauth-discovery-07) and OpenId Connect metadata
  (http://openid.net/specs/openid-connect-discovery-1_0.html). It also allows APIs to force
  metadata update.


  """
  use Application

  def start(_type, _args) do
    Oauth2MetadataUpdater.Supervisor.start_link(name: Oauth2MetadataUpdater.Supervisor)
  end

  def get_claim(issuer, claim) do
    Oauth2MetadataUpdater.Metadata.get_claim(issuer, claim)
  end

  def get_all_claims(issuer) do
    Oauth2MetadataUpdater.Metadata.get_claim(issuer)
  end

  def get_jwks(issuer) do
    Oauth2MetadataUpdater.Jwks.get_jwks(issuer)
  end

  def update_metadata(issuer) do
    GenServer.call(String.to_atom("Oauth2MetadataUpdater-" <> issuer), :update_metadata)
  end
end
