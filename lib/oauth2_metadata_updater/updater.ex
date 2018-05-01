defmodule Oauth2MetadataUpdater.Updater do
  use GenServer

  require Logger

  # client API
  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: :oauth2_metadata_updater)
  end

  def get_claim(issuer, claim) do
    update_metadata(issuer)

    [{_issuer, claims, _jwks, _last_update}] = :ets.lookup(:oauth2_metadata, issuer)

    claims[claim]
  end

  def get_all_claims(issuer) do
    update_metadata(issuer)

    [{_issuer, claims, _jwks, _last_update}] = :ets.lookup(:oauth2_metadata, issuer)

    claims
  end

  def get_jwks(issuer) do
    update_metadata(issuer)

    [{_issuer, _claims, jwks, _last_update}] = :ets.lookup(:oauth2_metadata, issuer)

    jwks
  end

  defp update_metadata(issuer) do
    case :ets.lookup(:oauth2_metadata, issuer) do
      [] -> GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer})
      [{_issuer, _claims, _jwks, last_update}] ->
        if System.system_time(:second) - last_update > 60 do
          GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer})
        end
    end
  end

  # server callbacks

  def init(state) do
    :ets.new(:oauth2_metadata, [:named_table, :set, :protected, read_concurrency: true])

    {:ok, state}
  end

  def handle_call({:update_metadata, issuer}, _from, state) do
    claims = request_and_process_metadata(issuer)

    jwks =
      if claims != nil and state[:resolve_jwks] do
        request_and_process_jwks(issuer, claims["jwks_uri"])
      else
        nil
      end

    :ets.insert(:oauth2_metadata, {issuer, claims, jwks, System.system_time(:second)})

    {:reply, :updated, state}
  end

  defp request_and_process_metadata(issuer) do
    #If the issuer identifier value contains a path component, any
    #terminating "/" MUST be removed before appending "/.well-known/" and
    #the well-known URI path suffix.
    issuer_uri = URI.parse(issuer)

    path =
      issuer_uri.path
      |> to_string()
      |> String.trim_trailing("/")

    metadata_uri = %{issuer_uri | path: "/.well-known/openid-configuration" <> path}

    with :ok <- https_scheme?(metadata_uri),
      {:ok, %HTTPoison.Response{body: body, status_code: 200}} <- HTTPoison.get(URI.to_string(metadata_uri)),
      {:ok, claims} <- Poison.decode(body),
      claims <- set_default_values(claims),
      :ok <- issuer_valid?(issuer, claims),
      :ok <- has_authorization_endpoint?(claims),
      :ok <- has_token_endpoint?(claims),
      :ok <- jwks_uri_valid?(claims),
      :ok <- has_response_types_supported?(claims),
      :ok <- has_token_endpoint_auth_signing_alg_values_supported?(claims),
      :ok <- has_revocation_endpoint_auth_signing_alg_values_supported?(claims),
      :ok <- has_introspection_endpoint_auth_signing_alg_values_supported?(claims),
      claims
    do
      Logger.info("#{__MODULE__}: OAuth2 metadata updated for issuer #{issuer}")

      claims
    else
      {:ok, %HTTPoison.Response{status_code: status_code}} ->
        Logger.error("#{__MODULE__}: invalid HTTP status code for issuer #{issuer} (HTTP code: #{status_code})")
        nil
      {:error, %HTTPoison.Error{} = error} ->
        Logger.error("#{__MODULE__}: could not retrieve or parse result for issuer #{issuer} (reason: #{HTTPoison.Error.message(error)})")
        nil
      {:error, reason} when is_binary(reason) ->
        Logger.error("#{__MODULE__}: could not retrieve or parse result for issuer #{issuer} (reason: #{reason})")
        nil
      _ ->
        Logger.error("#{__MODULE__}: could not retrieve or parse result for issuer #{issuer} (unknown reason)")
        nil
    end
  end

  defp https_scheme?(%URI{scheme: "https"}), do: :ok
  defp https_scheme?(_), do: {:error, "URI scheme is not https"}

  defp set_default_values(claims) do
    claims
    |> Map.put_new("response_modes_supported", ["query","fragment"])
    |> Map.put_new("grant_types_supported", ["authorization_code", "implicit"])
    |> Map.put_new("token_endpoint_auth_methods_supported", ["client_secret_basic"])
    |> Map.put_new("revocation_endpoint_auth_methods_supported", ["client_secret_basic"])
  end

  defp issuer_valid?(issuer, claims) do
    issuer_claim_uri = URI.parse(to_string(claims["issuer"]))

    if issuer == claims["issuer"] and issuer_claim_uri.query == nil and issuer_claim_uri.fragment == nil do
      :ok
    else
      {:error, "incorrect issuer value in claims"}
    end
  end

  defp has_authorization_endpoint?(claims) do
    if Map.has_key?(claims, "authorization_endpoint") or
       (
         "authorization_code" not in claims["grant_types_supported"] and
         "implicit" not in claims["grant_types_supported"]
       ) do
      :ok
    else
      {:error, "Missing authorization_endpoint claim"}
    end
  end

  defp has_token_endpoint?(claims) do
    if Map.has_key?(claims, "token_endpoint") or ["token"] == claims["response_types_supported"] do
      :ok
    else
      {:error, "Missing token_endpoint claim"}
    end
  end

  defp jwks_uri_valid?(%{} = claims) do
    if Map.has_key?(claims, "jwks_uri") do
      case URI.parse(to_string(claims["jwks_uri"])) do
        %URI{scheme: "https"} -> :ok
        _ -> {:error, "JWKS URI does not use https scheme"}
      end
    else
      :ok
    end
  end

  defp has_response_types_supported?(claims) do
    if is_list(claims["response_types_supported"]) do
      :ok
    else
      {:error, "Missing response_types_supported claim"}
    end
  end

  defp has_token_endpoint_auth_signing_alg_values_supported?(claims) do
    if "private_key_jwt" in claims["token_endpoint_auth_methods_supported"] or
       "client_secret_jwt" in claims["token_endpoint_auth_methods_supported"]
    do
      if is_list(claims["token_endpoint_auth_signing_alg_values_supported"]) and
         "none" not in claims["token_endpoint_auth_signing_alg_values_supported"]
      do
        :ok
      else
        {:error, "Missing token_endpoint_auth_signing_alg_values_supported claim or forbidden \"none\" value"}
      end
    else
      :ok
    end
  end

  defp has_revocation_endpoint_auth_signing_alg_values_supported?(claims) do
    if "private_key_jwt" in claims["revocation_endpoint_auth_methods_supported"] or
       "client_secret_jwt" in claims["revocation_endpoint_auth_methods_supported"]
    do
      if is_list(claims["revocation_endpoint_auth_signing_alg_values_supported"]) and
         "none" not in claims["revocation_endpoint_auth_signing_alg_values_supported"]
      do
        :ok
      else
        {:error, "Missing revocation_endpoint_auth_signing_alg_values_supported claim"}
      end
    else
      :ok
    end
  end

  defp has_introspection_endpoint_auth_signing_alg_values_supported?(claims) do
    if is_list(claims["introspection_endpoint_auth_methods_supported"]) and
       (
        "private_key_jwt" in claims["introspection_endpoint_auth_methods_supported"] or
        "client_secret_jwt" in claims["introspection_endpoint_auth_methods_supported"]
       )
    do
      if is_list(claims["introspection_endpoint_auth_signing_alg_values_supported"]) and
         "none" not in claims["introspection_endpoint_auth_signing_alg_values_supported"]
      do
        :ok
      else
        {:error, "Missing introspection_endpoint_auth_signing_alg_values_supported claim"}
      end
    else
      :ok
    end
  end

  defp request_and_process_jwks(issuer, nil) do
    Logger.warn("#{__MODULE__}: no jwks URI for issuer #{issuer}")
    nil
  end

  defp request_and_process_jwks(issuer, jwks_uri) do
    with {:ok, response} <- HTTPoison.get(jwks_uri),
         {:ok, jwks} <- Poison.decode(response.body)
    do
      Logger.info("#{__MODULE__}: OAuth2 jwks updated for issuer #{issuer}")

      jwks
    else
      {:error, %HTTPoison.Error{} = error} ->
        Logger.error("#{__MODULE__}: could not retrieve or parse jwks URI for issuer #{issuer} (reason: #{HTTPoison.Error.message(error)})")
        nil
      {:error, reason} when is_binary(reason) ->
        Logger.error("#{__MODULE__}: could not retrieve or parse jwks URI for issuer #{issuer} (reason: #{reason})")
        nil
      _ ->
        Logger.error("#{__MODULE__}: could not retrieve or parse jwks URI for issuer #{issuer} (unknown reason)")
        nil
    end
  end

end
