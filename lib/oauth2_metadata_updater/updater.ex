defmodule Oauth2MetadataUpdater.Updater do
  use GenServer

  require Logger

  def start_link(opts) do
    if check_issuer_url(opts[:issuer]) do
      GenServer.start_link(__MODULE__, opts, [name: String.to_atom(opts[:issuer])])
    else
      Logger.error "#{__MODULE__}: invalid URL for issuer #{opts[:issuer]} (ensure using https scheme)"
      :ignore
    end
  end

  def init(state) do
    send(self(), :update_metadata)
    {:ok, state}
  end

  def schedule(refresh_interval) do
    Process.send_after(self(), :update_metadata, refresh_interval * 1000)
  end

  def handle_info(:update_metadata, state) do
    update_metadata(state)
    schedule(state[:refresh_interval])
    {:noreply, state}
  end

  def update_metadata(state) do
    request_and_process_metadata(state)

    if state[:resolve_jwks] do
      request_and_process_jwks(state)
    end
  end

  defp check_issuer_url(url) do
    case URI.parse(url) do
      %URI{scheme: "https"} -> true
      _ -> false
    end
  end

  defp request_and_process_metadata(state) do
    with {:ok, response} <- HTTPoison.get(state[:issuer] <> state[:well_known_path]),
      {:ok, json} <- Poison.decode(response.body),
      {:ok, json} <- url_issuer_match?(state, json)
    do
      Oauth2MetadataUpdater.Metadata.update_metadata(state[:issuer], json)
      Logger.info("#{__MODULE__}: OAuth2 metadata updated for issuer #{state[:issuer]}")
    else
      {:error, reason} -> Logger.error("#{__MODULE__}: could not retrieve or parse result for issuer #{state[:issuer]}")
    end
  end

  defp url_issuer_match?(state, json) do
    if state[:issuer] == to_string(json["issuer"]) do
      {:ok, json}
    else
      {:error, "issuer advertised does not match its own URI"}
    end
  end

  defp request_and_process_jwks(state) do
    case Oauth2MetadataUpdater.Metadata.get_claim(state[:issuer], "jwks_uri") do
      nil -> Logger.warn "#{__MODULE__}: no jwks URI for issuer #{state[:issuer]}"
      jwks_uri ->
        with {:ok, response} <- HTTPoison.get(jwks_uri),
          {:ok, json} <- Poison.decode(response.body)
        do
          Oauth2MetadataUpdater.Jwks.update_jwks(state[:issuer], json)
          Logger.info("#{__MODULE__}: OAuth2 jwks updated for issuer #{state[:issuer]}")
        else
          {:error, reason} -> Logger.error("#{__MODULE__}: could not retrieve or parse jwks URI for issuer #{state[:issuer]}")
        end
    end
  end

end
