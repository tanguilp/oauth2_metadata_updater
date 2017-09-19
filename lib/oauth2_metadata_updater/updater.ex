defmodule Oauth2MetadataUpdater.Updater do
  use GenServer

  require Logger

  def start_link(opts) do
    if check_provider_url(opts[:target]) do
      GenServer.start_link(__MODULE__,
                           [
                             provider: opts[:name],
                             target: opts[:target],
                             refresh_interval: opts[:refresh_interval]
                           ],
                           [name: opts[:name]])
    else
      Logger.error "#{__MODULE__}: invalid URL for provider #{opts[:name]} (ensure using https scheme)"
      :ignore
    end
  end

  def init(state) do
    update_metadata(state[:provider], state[:target], state[:resolve_jwks])
    schedule(state[:refresh_interval])
    {:ok, state}
  end

  def schedule(refresh_interval) do
    Process.send_after(self(), :update_metadata, refresh_interval * 1000)
  end

  def handle_info(:update_metadata, state) do
    update_metadata(state[:provider], state[:target], state[:resolve_jwks])
    schedule(state[:refresh_interval])
    {:noreply, state}
  end

  def update_metadata(provider, url, resolve_jwks) do

    request_and_process_metadata(provider, url)
    
    if resolve_jwks do
      request_and_process_jwks(provider)
    end
  end

  defp check_provider_url(url) do
    case URI.parse(url) do
      %URI{scheme: "https"} -> true
      _ -> false
    end
  end

  defp request_and_process_metadata(provider, url) do
    with {:ok, response} <- HTTPoison.get(url),
      {:ok, json} <- Poison.decode(response.body),
      {:ok, json} <- url_issuer_match?(url, json)
    do
      Oauth2MetadataUpdater.Metadata.update_metadata(provider, json)
      Logger.info("#{__MODULE__}: OAuth2 metadata updated for provider #{provider}")
    else
      {:error, reason} -> Logger.error("#{__MODULE__}: could not retrieve or parse result for provider #{provider} (#{reason})")
    end
  end

  defp url_issuer_match?(url, json) do
    if url == to_string(json["issuer"]) <> "/.well-known/openid-configuration" do
      {:ok, json}
    else
      {:error, "issuer and provider URI do not match"}
    end
  end

  defp request_and_process_jwks(provider) do
    :ok
  end

end
