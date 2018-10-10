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
    import Supervisor.Spec

    children = [worker(Oauth2MetadataUpdater.Updater, [])]

    {:ok, _} =
      Supervisor.start_link(children, strategy: :one_for_one, name: :oauth2_metadata_updater_sup)
  end

  defdelegate get_claim(issuer, claim, opts \\ []), to: Oauth2MetadataUpdater.Updater
  defdelegate get_all_claims(issuer, opts \\  []), to: Oauth2MetadataUpdater.Updater
  defdelegate get_jwks(issuer, opts \\ []), to: Oauth2MetadataUpdater.Updater

end
