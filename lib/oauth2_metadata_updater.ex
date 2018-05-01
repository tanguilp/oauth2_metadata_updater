defmodule Oauth2MetadataUpdater do
  @moduledoc """
  Keeps OAuth2 / OpenID Connect metadata up to date

  This module periodically updates OAuth2 metadata (OAuth 2.0 Authorization Server Metadata
  draft-ietf-oauth-discovery-07) and OpenId Connect metadata
  (http://openid.net/specs/openid-connect-discovery-1_0.html). It also allows APIs to force
  metadata update.


  """
  use Application

  @default_options [
    refresh_interval: 3600,
    resolve_jwks: true
  ]

  def start(_type, _args) do
    Oauth2MetadataUpdater.Updater.start_link(
      Keyword.merge(@default_options, Application.get_all_env(:oauth2_metadata_updater))
    )
  end

  defdelegate get_claim(issuer, claim), to: Oauth2MetadataUpdater.Updater
  defdelegate get_all_claims(issuer), to: Oauth2MetadataUpdater.Updater
  defdelegate get_jwks(issuer), to: Oauth2MetadataUpdater.Updater
end
