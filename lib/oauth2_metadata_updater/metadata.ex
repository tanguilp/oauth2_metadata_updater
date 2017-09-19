defmodule Oauth2MetadataUpdater.Metadata do
  use Agent

  def start_link do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @doc "Get a claim for a given OAuth2 provider"
  def get_claim(provider, claim) do
    Agent.get(__MODULE__, fn map -> map[provider][claim] end)
  end

  @doc "Get all claims of a given OAuth2 provider"
  def get_claim(provider) do
    Agent.get(__MODULE__, fn map -> map[provider] end)
  end

  @doc "Get a claim from OAuth2 metadata provider"
  def update_metadata(provider, metadata) do
    Agent.update(__MODULE__, &Map.put(&1, provider, metadata))
  end
end
