defmodule Oauth2MetadataUpdater.Metadata do
  use Agent

  def start_link do
    Agent.start_link(fn -> %{} end, name: __MODULE__)
  end

  @doc "Get a claim for a given OAuth2 issuer"
  def get_claim(issuer, claim) do
    Agent.get(__MODULE__, fn map -> map[issuer][claim] end)
  end

  @doc "Get all claims of a given OAuth2 issuer"
  def get_claim(issuer) do
    Agent.get(__MODULE__, fn map -> map[issuer] end)
  end

  @doc "Update metadata of an OAuth2 issuer"
  def update_metadata(issuer, metadata) do
    Agent.update(__MODULE__, &Map.put(&1, issuer, metadata))
  end
end
