defmodule Oauth2MetadataUpdater.Updater do
  use GenServer

  require Logger

  @allowed_suffixes \
    File.stream!("lib/oauth2_metadata_updater/well-known-uris-1.csv", [:read])
    |> Stream.drop(1) #csv header line
    |> Stream.map(fn(line) -> List.first(String.split(line, ",")) end)
    |> Enum.into([])

  @default_opts [
    suffix: "oauth-authorization-server",
    refresh_interval: 3600,
    min_refresh_interval: 10,
    resolve_jwks: true,
    on_refresh_failure: :keep_metadata,
    url_construction: :standard,
    ssl: []
  ]

  # client API
  def start_link() do
    GenServer.start_link(__MODULE__, [], name: :oauth2_metadata_updater)
  end

  @spec get_claim(String.t, String.t, Keyword.t) :: {:ok, String.t | nil} | {:error, Exception.t}
  def get_claim(issuer, claim, opts) do
    opts = Keyword.merge(@default_opts, opts)

    update_res = unless metadata_up_to_date?(issuer, opts), do: GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts})

    case update_res do
      {:error, e} ->
        {:error, e}
      _ ->
        [{_issuer, _last_update_time, metadata, _jwks}] = :ets.lookup(:oauth2_metadata, issuer)
        {:ok, metadata[claim]}
    end
  end

  @spec get_all_claims(String.t, Keyword.t) :: {:ok, map() | nil} | {:error, Exception.t}
  def get_all_claims(issuer, opts) do
    opts = Keyword.merge(@default_opts, opts)

    update_res = unless metadata_up_to_date?(issuer, opts), do: GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts})

    case update_res do
      {:error, e} -> {:error, e}
      _ ->
        [{_issuer, _last_update_time, metadata, _jwks}] = :ets.lookup(:oauth2_metadata, issuer)

        {:ok, metadata}
    end
  end

  @spec get_jwks(String.t, Keyword.t) :: {:ok, map() | nil} | {:error, Exception.t}
  def get_jwks(issuer, opts) do
    opts = Keyword.merge(@default_opts, opts)

    update_res = unless metadata_up_to_date?(issuer, opts), do: GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts})

    case update_res do
      {:error, e} -> {:error, e}
      _ ->
        [{_issuer, _last_update_time, _metadata, jwks}] = :ets.lookup(:oauth2_metadata, issuer)

        {:ok, jwks}
    end
  end

  defp metadata_up_to_date?(issuer, opts) do
    case :ets.lookup(:oauth2_metadata, issuer) do
      [{_issuer, last_update_time, metadata, _jwks}] ->
        if now() - last_update_time < opts[:refresh_interval] or
           (metadata == nil and
           now() - last_update_time < opts[:min_refresh_interval])
        do
          true
        else
          false
        end

      _ -> false
    end
  end

  # server callbacks

  def init(_opts) do
    HTTPoison.start()

    :ets.new(:oauth2_metadata, [:set, :named_table, :protected, read_concurrency: true])

    unless is_nil(Application.get_env(:oauth2_metadata_updater, :preload)) do
      Enum.each(Application.get_env(:oauth2_metadata_updater, :preload),
                fn {issuer, opts} -> GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts}) end)
    end

    {:ok, %{}}
  end

  def handle_call({:update_metadata, issuer, opts}, _from, state) do
    # the metadata may have already been updated but the HTTP request
    # was in-flight and that method called meanwhile
    if metadata_up_to_date?(issuer, opts) do
      {:reply, :ok, state}
    else
      case request_and_process_metadata(issuer, opts) do
        claims when is_map(claims) ->

          jwks =
            if opts[:resolve_jwks] == true do
              request_and_process_jwks(issuer, claims["jwks_uri"], opts)
            else
              nil
            end

          :ets.insert(:oauth2_metadata, {issuer, now(), claims, jwks})

          {:reply, :ok, state}

        {:error, error} ->
          on_refresh_failure = opts[:on_refresh_failure]

          case :ets.lookup(:oauth2_metadata, issuer) do
          # silently fails and returns already saved (and outdated?) metadata
          [{_issuer, _last_update_time, metadata, _jwks}] when not is_nil metadata and on_refresh_failure == :keep_metadata ->
            :ets.update_element(:oauth2_metadata, issuer, {2, now()})
            Logger.warn("#{__MODULE__}: metadata for issuer #{issuer} can no longer be reached")
            {:reply, :ok, state}
          _ ->
            :ets.insert(:oauth2_metadata, {issuer, now(), nil, nil})
            {:reply, {:error, error}, state}
          end
      end
    end
  end

  defp request_and_process_metadata(issuer, opts) do
    with :ok <- suffix_authorized?(opts[:suffix]),
         {:ok, metadata_uri} <- build_url(issuer, opts),
         :ok <- https_scheme?(metadata_uri),
         {:ok, %HTTPoison.Response{body: body, status_code: 200, headers: headers}} <- HTTPoison.get(URI.to_string(metadata_uri), [], hackney: [ssl_options: opts[:ssl]]),
         :ok <- content_type_application_json?(headers),
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
           claims
    else
      {:ok, %HTTPoison.Response{status_code: status_code}} ->
        {:error, "Invalid HTTP response code: #{status_code}"}
      {:error, error} ->
        {:error, error}
    end
  end

  defp suffix_authorized?(suffix) when suffix in @allowed_suffixes, do: :ok
  defp suffix_authorized?(suffix), do: {:error, "Unauthorized suffix: \"#{suffix}\""}

  defp build_url(issuer, opts) do
    # If the issuer identifier value contains a path component, any
    # terminating "/" MUST be removed before appending "/.well-known/" and
    # the well-known URI path suffix.
    issuer_uri = URI.parse(issuer)

    path =
      issuer_uri.path
      |> to_string()
      |> String.trim_trailing("/")

    case opts[:url_construction] do
      :standard ->
        {:ok, %{issuer_uri | path: "/.well-known/" <> opts[:suffix] <> path}}
      :non_standard_append ->
        {:ok, %{issuer_uri | path: path <> "/.well-known/" <> opts[:suffix]}}
    end
  end

  defp https_scheme?(%URI{scheme: "https"}), do: :ok
  defp https_scheme?(_), do: {:error, "URI scheme is not https"}

  defp content_type_application_json?(headers) do
    case List.keyfind(headers, "Content-Type", 0) do
      {_, "application/json"} -> :ok

      _ -> {:error, "Invalid response content type, must be application/json"}
    end
  end

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
    if not Map.has_key?(claims, "authorization_endpoint") and
      Enum.any?(claims["grant_types_supported"], fn gt -> OAuth2Utils.uses_authorization_endpoint?(gt) end) do
      {:error, "missing authorization_endpoint claim"}
    else
      :ok
    end
  end

  defp has_token_endpoint?(claims) do
    if Map.has_key?(claims, "token_endpoint") or ["implicit"] == claims["grant_types_supported"] do
      :ok
    else
      {:error, "missing token_endpoint claim"}
    end
  end

  defp jwks_uri_valid?(%{"jwks_uri" => nil}), do: :ok
  defp jwks_uri_valid?(%{"jwks_uri" => jwks_uri}) when is_binary(jwks_uri) do
    case https_scheme?(URI.parse(jwks_uri)) do
      :ok ->
        :ok
      {:error, _} ->
        {:error, "JWKS URI does not use https scheme"}
    end
  end

  defp has_response_types_supported?(claims) do
    if is_list(claims["response_types_supported"]) do
      :ok
    else
      {:error, message: "missing response_types_supported claim"}
    end
  end

  defp has_token_endpoint_auth_signing_alg_values_supported?(claims) do
    if "private_key_jwt" in claims["token_endpoint_auth_methods_supported"] or
         "client_secret_jwt" in claims["token_endpoint_auth_methods_supported"] do
      if is_list(claims["token_endpoint_auth_signing_alg_values_supported"]) and
           "none" not in claims["token_endpoint_auth_signing_alg_values_supported"] do
        :ok
      else
        {:error, "missing token_endpoint_auth_signing_alg_values_supported claim or forbidden \"none\" value"}
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

  defp request_and_process_jwks(issuer, nil, _opts) do
    Logger.info("#{__MODULE__}: no jwks URI for issuer #{issuer}")
    nil
  end

  defp request_and_process_jwks(_issuer, jwks_uri, opts) do
    response = HTTPoison.get!(jwks_uri, [], opts[:ssl])

    Poison.decode!(response.body)
  end

  defp now(), do: System.system_time(:second)

end
