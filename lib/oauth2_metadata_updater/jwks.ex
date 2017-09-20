defmodule Oauth2MetadataUpdater.Jwks do
  use Agent

  def start_link do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @doc "Get jwks for a given OAuth2 provider"
  def get_jwks(provider) do
    Agent.get(__MODULE__, fn map -> map[provider] end)
  end

  @doc "Update JWKS for a given provider"
  def update_jwks(provider, jwks) do
    Agent.update(__MODULE__, &Map.put(&1, provider, jwks))
  end
end
