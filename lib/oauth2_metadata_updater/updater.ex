defmodule Oauth2MetadataUpdater.Updater do
  use GenServer

  require Logger

  @allowed_suffixes \
    File.stream!("lib/oauth2_metadata_updater/well-known-uris-1.csv", [:read]) \
    |> Stream.drop(1) #csv header line
    |> Stream.map(fn(line) -> List.first(String.split(line, ",")) end)                  \
    |> Enum.into([])

  # client API
  def start_link() do
    GenServer.start_link(__MODULE__, [], name: :oauth2_metadata_updater)
  end

  def get_claim(issuer, claim, opts \\ []) do
    metadata = GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts})

    metadata[:claims][claim]
  end

  def get_all_claims(issuer, opts \\ []) do
    metadata = GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts})

    metadata[:claims]
  end

  def get_jwks(issuer, opts \\ []) do
    metadata = GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts})

    metadata[:jwks]
  end

  # server callbacks

  def init(_opts) do
    {:ok, %{}}
  end

  def handle_call({:update_metadata, issuer, opts}, _from, state) do
    state =
      if do_update?(issuer, state) do
        case request_and_process_metadata(issuer, opts) do
          {:ok, claims} ->
            jwks =
              if claims != nil and Application.get_env(:oauth2_metadata_updater, :resolve_jwks, true) do
                case request_and_process_jwks(issuer, claims["jwks_uri"]) do
                  {:ok, jwks} -> jwks
                  {:error, reason} ->
                    Logger.error("#{__MODULE__}: failed to load JWKS for \"#{issuer}\" (reason: #{reason})")
                    nil
                end
              else
                nil
              end

            metadata =
              Keyword.new()
              |> Keyword.put(:claims, claims)
              |> Keyword.put(:jwks, jwks)
              |> Keyword.put(:last_updated, now())

            Map.put(state, issuer, metadata)

          {:error, reason} ->
            Logger.error("#{__MODULE__}: failed to load metadata for \"#{issuer}\" (reason: #{reason})")
            Map.put(state, issuer, [last_updated: now()])
        end
      else
        state
      end

    {:reply, state[issuer], state}
  end

  defp do_update?(issuer, state) do
    case state[issuer] do
      nil -> true

      metadata ->
        if now() - metadata[:last_updated] > Application.get_env(:oauth2_metadata_updater, :refresh_interval, 3600) or
           (metadata[:claims] == nil and
           now() - metadata[:last_updated] > Application.get_env(:oauth2_metadata_updater, :min_refresh_interval, 30))
        do
          true
        else
          false
        end
    end
  end

  defp request_and_process_metadata(issuer, opts) do
    # If the issuer identifier value contains a path component, any
    # terminating "/" MUST be removed before appending "/.well-known/" and
    # the well-known URI path suffix.
    issuer_uri = URI.parse(issuer)

    path =
      issuer_uri.path
      |> to_string()
      |> String.trim_trailing("/")

    suffix =
      if opts[:suffix] in @allowed_suffixes do
        opts[:suffix]
      else
        "oauth-authorization-server"
      end

    metadata_uri = %{issuer_uri | path: "/.well-known/" <> suffix <> path}

    with :ok <- https_scheme?(metadata_uri),
         {:ok, %HTTPoison.Response{body: body, status_code: 200}} <-
           HTTPoison.get(URI.to_string(metadata_uri)),
         {:ok, claims} <- Poison.decode(body),
         claims <- set_default_values(claims),
         :ok <- issuer_valid?(issuer, claims),
         :ok <- has_authorization_endpoint?(claims),
         :ok <- has_token_endpoint?(claims),
         :ok <- jwks_uri_valid?(claims),
         :ok <- has_response_types_supported?(claims),
         :ok <- has_token_endpoint_auth_signing_alg_values_supported?(claims),
         :ok <- has_revocation_endpoint_auth_signing_alg_values_supported?(claims),
         :ok <- has_introspection_endpoint_auth_signing_alg_values_supported?(claims) do
           {:ok, claims}
    else
      {:ok, %HTTPoison.Response{status_code: status_code}} ->
        {:error, "invalid HTTP status code (#{status_code})"}

      {:error, %HTTPoison.Error{} = error} ->
        {:error, "#{HTTPoison.Error.message(error)}"}

      {:error, reason} when is_binary(reason) ->
        {:error, reason}

      _ ->
        {:error, "unknown error"}
    end
  end

  defp https_scheme?(%URI{scheme: "https"}), do: :ok
  defp https_scheme?(_), do: {:error, "URI scheme is not https"}

  defp set_default_values(claims) do
    claims
    |> Map.put_new("response_modes_supported", ["query", "fragment"])
    |> Map.put_new("grant_types_supported", ["authorization_code", "implicit"])
    |> Map.put_new("token_endpoint_auth_methods_supported", ["client_secret_basic"])
    |> Map.put_new("revocation_endpoint_auth_methods_supported", ["client_secret_basic"])
  end

  defp issuer_valid?(issuer, claims) do
    issuer_claim_uri = URI.parse(to_string(claims["issuer"]))

    if issuer == claims["issuer"] and issuer_claim_uri.query == nil and
         issuer_claim_uri.fragment == nil do
      :ok
    else
      {:error, "incorrect issuer value in claims"}
    end
  end

  defp has_authorization_endpoint?(claims) do
    if Map.has_key?(claims, "authorization_endpoint") or
         ("authorization_code" not in claims["grant_types_supported"] and
            "implicit" not in claims["grant_types_supported"]) do
      :ok
    else
      {:error, "missing authorization_endpoint claim"}
    end
  end

  defp has_token_endpoint?(claims) do
    if Map.has_key?(claims, "token_endpoint") or ["token"] == claims["response_types_supported"] do
      :ok
    else
      {:error, "missing token_endpoint claim"}
    end
  end

  defp jwks_uri_valid?(%{} = claims) do
    if Map.has_key?(claims, "jwks_uri") do
      if https_scheme?(URI.parse(to_string(claims["jwks_uri"]))) do
        :ok
      else
        {:error, "JWKS URI does not use https scheme"}
      end
    else
      :ok
    end
  end

  defp has_response_types_supported?(claims) do
    if is_list(claims["response_types_supported"]) do
      :ok
    else
      {:error, "missing response_types_supported claim"}
    end
  end

  defp has_token_endpoint_auth_signing_alg_values_supported?(claims) do
    if "private_key_jwt" in claims["token_endpoint_auth_methods_supported"] or
         "client_secret_jwt" in claims["token_endpoint_auth_methods_supported"] do
      if is_list(claims["token_endpoint_auth_signing_alg_values_supported"]) and
           "none" not in claims["token_endpoint_auth_signing_alg_values_supported"] do
        :ok
      else
        {:error,
         "missing token_endpoint_auth_signing_alg_values_supported claim or forbidden \"none\" value"}
      end
    else
      :ok
    end
  end

  defp has_revocation_endpoint_auth_signing_alg_values_supported?(claims) do
    if "private_key_jwt" in claims["revocation_endpoint_auth_methods_supported"] or
         "client_secret_jwt" in claims["revocation_endpoint_auth_methods_supported"] do
      if is_list(claims["revocation_endpoint_auth_signing_alg_values_supported"]) and
           "none" not in claims["revocation_endpoint_auth_signing_alg_values_supported"] do
        :ok
      else
        {:error, "missing revocation_endpoint_auth_signing_alg_values_supported claim"}
      end
    else
      :ok
    end
  end

  defp has_introspection_endpoint_auth_signing_alg_values_supported?(claims) do
    if is_list(claims["introspection_endpoint_auth_methods_supported"]) and
         ("private_key_jwt" in claims["introspection_endpoint_auth_methods_supported"] or
            "client_secret_jwt" in claims["introspection_endpoint_auth_methods_supported"]) do
      if is_list(claims["introspection_endpoint_auth_signing_alg_values_supported"]) and
           "none" not in claims["introspection_endpoint_auth_signing_alg_values_supported"] do
        :ok
      else
        {:error, "missing introspection_endpoint_auth_signing_alg_values_supported claim"}
      end
    else
      :ok
    end
  end

  defp request_and_process_jwks(issuer, nil) do
    Logger.info("#{__MODULE__}: no jwks URI for issuer #{issuer}")
    nil
  end

  defp request_and_process_jwks(_issuer, jwks_uri) do
    with {:ok, response} <- HTTPoison.get(jwks_uri),
         {:ok, jwks} <- Poison.decode(response.body) do
           {:ok, jwks}
    else
      {:error, %HTTPoison.Error{} = error} ->
        {:error, HTTPoison.Error.message(error)}

      {:error, reason} when is_binary(reason) ->
        {:error, reason}

      _ ->
        {:error, "unknown reason"}
    end
  end

  defp now(), do: System.system_time(:second)

end
