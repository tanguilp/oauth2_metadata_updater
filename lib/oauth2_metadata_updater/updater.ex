defmodule Oauth2MetadataUpdater.Updater do
  use GenServer

  require Logger

  def start_link(opts) do
    if check_issuer_url(opts[:issuer]) do
      GenServer.start_link(__MODULE__,
                           opts,
                           [name: String.to_atom("Oauth2MetadataUpdater-" <> opts[:issuer])])
    else
      Logger.error "#{__MODULE__}: invalid URL for issuer #{opts[:issuer]} (ensure using https scheme)"
      :ignore
    end
  end

  def init(state) do
    send(self(), :refresh)
    state = Keyword.put(state, :last_refresh_time, 0)
    {:ok, state}
  end

  def handle_call(:update_metadata, _from, state) do
    {state, updated} =
      if state[:last_refresh_time] + state[:forced_refresh_min_interval] < System.system_time(:second) do
        if state[:timer_ref] != nil do
          Process.cancel_timer(state[:timer_ref])
        end

        update_metadata(state)

        state = Keyword.put(state, :last_refresh_time, System.system_time(:second))

        {state, :updated}
      else
        {state, :not_updated}
      end

    {:reply, {:ok, updated}, state}
  end

  def handle_info(:refresh, state) do
    Task.start_link(__MODULE__, :update_metadata, [state])

    ref = Process.send_after(self(), :refresh, state[:refresh_interval] * 1000)

    state = state
    |> Keyword.put(:last_refresh_time, System.system_time(:second))
    |> Keyword.put(:timer_ref, ref)

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
    #If the issuer identifier value contains a path component, any
    #terminating "/" MUST be removed before appending "/.well-known/" and
    #the well-known URI path suffix.

    with {:ok, %HTTPoison.Response{body: body, status_code: 200}} <- HTTPoison.get(String.trim_trailing(state[:issuer], "/") <> state[:well_known_path]),
      # A successful response MUST use the 200 OK HTTP
      # status code and return a JSON object using the "application/json"
      # content type that contains a set of claims as its members that are a
      # subset of the metadata values defined in Section 2.  Other claims MAY
      # also be returned.
      {:ok, json} <- Poison.decode(body),
      {:ok, json} <- url_issuer_match?(state, json),
      {:ok, json} <- check_required_claims(json)
    do
      Oauth2MetadataUpdater.Metadata.update_metadata(state[:issuer], json)
      Logger.info("#{__MODULE__}: OAuth2 metadata updated for issuer #{state[:issuer]}")
    else
      {:error, %HTTPoison.Error{reason: reason}} -> Logger.error("#{__MODULE__}: could not retrieve or parse result for issuer #{state[:issuer]} (#{reason})")
      {:error, reason} -> Logger.error("#{__MODULE__}: could not retrieve or parse result for issuer #{state[:issuer]} (#{reason})")
    end
  end

  defp url_issuer_match?(state, json) do
    if state[:issuer] == to_string(json["issuer"]) do
      {:ok, json}
    else
      {:error, "issuer advertised does not match its own URI"}
    end
  end

  defp check_required_claims(json) do
    if Map.has_key?(json, "issuer") and
       Map.has_key?(json, "authorization_endpoint") and
       Map.has_key?(json, "response_types_supported") and
       (Map.has_key?(json, "token_endpoint") or ["token"] == json["response_types_supported"]) do
      {:ok, json}
    else
      {:error, "missing claim in issuer JSON response"}
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
          {:error, %HTTPoison.Error{reason: reason}} ->
            Logger.error("#{__MODULE__}: could not retrieve or parse jwks URI for issuer #{state[:issuer]} (#{reason})")
          {:error, reason} ->
            Logger.error("#{__MODULE__}: could not retrieve or parse jwks URI for issuer #{state[:issuer]} (#{reason})")
        end
    end
  end

end
