defmodule Oauth2MetadataUpdater.Jwks do
  use Agent

  def start_link do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @doc "Get jwks for a given OAuth2 issuer"
  def get_jwks(issuer) do
    Agent.get(__MODULE__, fn map -> map[issuer] end)
  end

  @doc "Update JWKS for a given issuer"
  def update_jwks(issuer, jwks) do
    Agent.update(__MODULE__, &Map.put(&1, issuer, jwks))
  end
end
