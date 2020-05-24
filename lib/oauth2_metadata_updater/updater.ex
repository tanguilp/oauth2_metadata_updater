defmodule Oauth2MetadataUpdater.Updater do
  @moduledoc false

  use GenServer

  require Logger

  @allowed_suffixes \
    File.stream!("lib/oauth2_metadata_updater/well-known-uris-1.csv", [:read])
    |> Stream.drop(1) #csv header line
    |> Stream.map(fn(line) -> List.first(String.split(line, ",")) end)
    |> Enum.into([])

  @default_opts [
    suffix: "openid-configuration",
    refresh_interval: 3600,
    min_refresh_interval: 10,
    on_refresh_failure: :keep_metadata,
    url_construction: :standard,
    validation: :oidc
  ]

  @opts_to_hash [:suffix, :on_refresh_failure, :url_construction, :validation]

  # client API
  def start_link() do
    GenServer.start_link(__MODULE__, [], name: :oauth2_metadata_updater)
  end

  @spec get_metadata_value(String.t, String.t, Keyword.t) ::
  {:ok, any() | nil} |
  {:error, atom()}
  def get_metadata_value(issuer, claim, opts) do
    opts = Keyword.merge(@default_opts, opts)

    update_res = unless metadata_up_to_date?(issuer, opts), do: GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts})

    case update_res do
      {:error, e} ->
        {:error, e}

      _ ->
        opts_thumbprint = opts_thumbprint(opts)

        case :ets.lookup(:oauth2_metadata, issuer) do
          [{_issuer, _last_update_time, {:error, error}, _opts_thumbprint}] ->
            {:error, error}

          [{_issuer, _last_update_time, metadata, ^opts_thumbprint}] ->
            {:ok, metadata[claim]}

          _ ->
            raise "The following options for the same issuer shall not be changed between " <>
              "requests: " <> (@opts_to_hash |> Enum.map(&to_string/1) |> Enum.join(", "))
        end
    end
  end

  @spec get_metadata(String.t, Keyword.t) :: {:ok, map() | nil} | {:error, atom()}
  def get_metadata(issuer, opts) do
    opts = Keyword.merge(@default_opts, opts)

    update_res =
      unless metadata_up_to_date?(issuer, opts) do
        GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts})
      end

    case update_res do
      {:error, e} ->
        {:error, e}

      _ ->
        opts_thumbprint = opts_thumbprint(opts)

        case :ets.lookup(:oauth2_metadata, issuer) do
          [{_issuer, _last_update_time, {:error, error}, _opts_thumbprint}] ->
            {:error, error}

          [{_issuer, _last_update_time, metadata, ^opts_thumbprint}] ->
            {:ok, metadata}

          _ ->
            raise "The following options for the same issuer shall not be changed between " <>
              "requests: #{@opts_to_hash}"
        end
    end
  end

  defp metadata_up_to_date?(issuer, opts) do
    case :ets.lookup(:oauth2_metadata, issuer) do
      [{_issuer, last_update_time, {:error, _}, _opts_thumbprint}] ->
        if now() - last_update_time < opts[:min_refresh_interval], do: true, else: false

      [{_issuer, last_update_time, _metadata, _opts_thumbprint}] ->
        if now() - last_update_time < opts[:refresh_interval], do: true, else: false

      _ -> false
    end
  end

  # server callbacks

  @doc """
  """

  @impl true
  def init(_opts) do
    :ets.new(:oauth2_metadata, [:set, :named_table, :protected, read_concurrency: true])

    unless is_nil(Application.get_env(:oauth2_metadata_updater, :preload)) do
      Enum.each(Application.get_env(:oauth2_metadata_updater, :preload),
                fn {issuer, opts} -> GenServer.call(:oauth2_metadata_updater, {:update_metadata, issuer, opts}) end)
    end

    {:ok, %{}}
  end

  @doc """
  """

  @impl true
  def handle_call({:update_metadata, issuer, opts}, _from, state) do
    # the metadata may have already been updated but the HTTP request
    # was in-flight and that method called meanwhile
    if metadata_up_to_date?(issuer, opts) do
      {:reply, :ok, state}
    else
      case request_and_process_metadata(issuer, opts) do
        claims when is_map(claims) ->
          :ets.insert(:oauth2_metadata, {issuer, now(), claims, opts_thumbprint(opts)})

          {:reply, :ok, state}

        {:error, error} ->
          on_refresh_failure = opts[:on_refresh_failure]

          case :ets.lookup(:oauth2_metadata, issuer) do
            [{_issuer, _last_update_time, metadata, _opts_thumbprint}] when not is_nil metadata
              and on_refresh_failure == :keep_metadata ->
            :ets.update_element(:oauth2_metadata, issuer, {2, now()})

            Logger.warn("#{__MODULE__}: metadata for issuer #{issuer} can no longer be reached")

            {:reply, :ok, state}

          _ ->
            :ets.insert(:oauth2_metadata, {issuer, now(), {:error, error}, opts_thumbprint(opts)})

            {:reply, {:error, error}, state}
          end
      end
    end
  end



  defp request_and_process_metadata(issuer, opts) do
    with :ok <- suffix_authorized?(opts[:suffix]),
         {:ok, metadata_uri} <- build_url(issuer, opts),
         :ok <- https_scheme?(metadata_uri),
         http_client = opts |> tesla_middlewares() |> Tesla.client(),
         {:ok, %Tesla.Env{body: claims, status: 200, headers: headers}} <- Tesla.get(http_client, URI.to_string(metadata_uri)),
         :ok <- content_type_application_json?(headers),
         claims <- set_default_values(claims),
         :ok <- issuer_valid?(issuer, claims),
         :ok <- has_authorization_endpoint?(claims),
         :ok <- has_token_endpoint?(claims),
         :ok <- oidc_has_jwks_uri?(claims, opts[:validation]),
         :ok <- jwks_uri_valid?(claims),
         :ok <- has_response_types_supported?(claims),
         :ok <- oidc_has_subject_types_supported?(claims, opts[:validation]),
         :ok <- has_token_endpoint_auth_signing_alg_values_supported?(claims),
         :ok <- has_revocation_endpoint_auth_signing_alg_values_supported?(claims),
         :ok <- has_introspection_endpoint_auth_signing_alg_values_supported?(claims),
         :ok <- oidc_has_id_token_signing_alg_values_supported?(claims, opts[:validation]) do
           claims
    else
      {:ok, %Tesla.Env{}} ->
        {:error, :invalid_http_response_code}

      {:error, error} ->
        {:error, error}
    end
  end

  defp suffix_authorized?(suffix) when suffix in @allowed_suffixes, do: :ok
  defp suffix_authorized?(_), do: {:error, :invalid_suffix}

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
  defp https_scheme?(_), do: {:error, :invalid_uri_scheme}

  defp content_type_application_json?(headers) do
    headers
    |> Enum.map(fn {k, v} -> {String.downcase(k), v} end)
    |> List.keyfind("content-type", 0)
    |> case do
      nil ->
        {:error, :invalid_response_content_type}

      {_, media_type} ->
        case ContentType.content_type(media_type) do
          {:ok, "application", "json", _} -> :ok
          _ -> {:error, :invalid_response_content_type}
        end
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
      {:error, :invalid_issuer_value}
    end
  end

  defp has_authorization_endpoint?(claims) do
    if not Map.has_key?(claims, "authorization_endpoint") and
      Enum.any?(claims["grant_types_supported"], fn gt -> OAuth2Utils.uses_authorization_endpoint?(gt) end) do
      {:error, :missing_authorization_endpoint}
    else
      :ok
    end
  end

  defp has_token_endpoint?(claims) do
    if Map.has_key?(claims, "token_endpoint") or ["implicit"] == claims["grant_types_supported"] do
      :ok
    else
      {:error, :missing_token_endpoint}
    end
  end

  defp oidc_has_jwks_uri?(_, :oauth2), do: :ok
  defp oidc_has_jwks_uri?(%{"jwks_uri" => jwks_uri}, :oidc) when is_binary(jwks_uri), do: :ok
  defp oidc_has_jwks_uri?(_, :oidc), do: {:error, :missing_jwks_uri}

  defp jwks_uri_valid?(%{"jwks_uri" => nil}), do: :ok
  defp jwks_uri_valid?(%{"jwks_uri" => jwks_uri}) when is_binary(jwks_uri) do
    case https_scheme?(URI.parse(jwks_uri)) do
      :ok ->
        :ok
      {:error, _} ->
        {:error, :jwks_invalid_uri_scheme}
    end
  end

  defp has_response_types_supported?(claims) do
    if is_list(claims["response_types_supported"]) do
      :ok
    else
      {:error, :missing_response_types_supported}
    end
  end

  defp oidc_has_subject_types_supported?(_, :oauth2), do: :ok
  defp oidc_has_subject_types_supported?(claims, :oidc) do
    if is_list(claims["subject_types_supported"]) do
      :ok
    else
      {:error, :missing_subject_types_supported}
    end
  end

  defp has_token_endpoint_auth_signing_alg_values_supported?(claims) do
    if "private_key_jwt" in claims["token_endpoint_auth_methods_supported"] or
         "client_secret_jwt" in claims["token_endpoint_auth_methods_supported"] do
      if is_list(claims["token_endpoint_auth_signing_alg_values_supported"]) do
        if "none" not in claims["token_endpoint_auth_signing_alg_values_supported"] do
          :ok
        else
          {:error, :none_value_forbidden_token_endpoint_auth_signing_values_supported}
        end
      else
        {:error, :missing_token_endpoint_auth_signing_alg_values_supported}
      end
    else
      :ok
    end
  end

  defp has_revocation_endpoint_auth_signing_alg_values_supported?(claims) do
    if "private_key_jwt" in claims["revocation_endpoint_auth_methods_supported"] or
         "client_secret_jwt" in claims["revocation_endpoint_auth_methods_supported"] do
      if is_list(claims["revocation_endpoint_auth_signing_alg_values_supported"]) do 
        if "none" not in claims["revocation_endpoint_auth_signing_alg_values_supported"] do
          :ok
        else
          {:error, :none_value_forbidden_revocation_endpoint_auth_signing_alg_values_supported}
        end
      else
        {:error, :missing_revocation_endpoint_auth_signing_alg_values_supported}
      end
    else
      :ok
    end
  end

  defp has_introspection_endpoint_auth_signing_alg_values_supported?(claims) do
    if is_list(claims["introspection_endpoint_auth_methods_supported"]) and
         ("private_key_jwt" in claims["introspection_endpoint_auth_methods_supported"] or
            "client_secret_jwt" in claims["introspection_endpoint_auth_methods_supported"]) do
      if is_list(claims["introspection_endpoint_auth_signing_alg_values_supported"]) do 
        if "none" not in claims["introspection_endpoint_auth_signing_alg_values_supported"] do
          :ok
        else
          {:error, :none_value_forbidden_introspection_endpoint_auth_signing_alg_values_supported}
        end
      else
        {:error, :missing_introspection_endpoint_auth_signing_alg_values_supported}
      end
    else
      :ok
    end
  end

  defp oidc_has_id_token_signing_alg_values_supported?(_, :oauth2), do: :ok
  defp oidc_has_id_token_signing_alg_values_supported?(claims, :oidc) do
    if is_list(claims["id_token_signing_alg_values_supported"]) do
      if "RS256" in claims["id_token_signing_alg_values_supported"] do
        :ok
      else
        {:error, :missing_rs256_alg_from_id_token_signing_alg_values_supported}
      end
    else
      {:error, :missing_id_token_signing_alg_values_supported}
    end
  end

  defp tesla_middlewares(opts) do
    Application.get_env(:oauth2_metadata_updater, :tesla_middlewares, [])
    ++ (opts[:tesla_middlewares] || [])
    ++ [Tesla.Middleware.JSON]
  end

  defp opts_thumbprint(opts) do
    opts
    |> Keyword.take(@opts_to_hash)
    |> Enum.into(%{})
    |> :erlang.phash2()
  end

  defp now(), do: System.system_time(:second)
end
