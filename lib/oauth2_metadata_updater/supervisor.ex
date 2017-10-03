defmodule Oauth2MetadataUpdater.Supervisor do
  use Supervisor
  
  import Supervisor.Spec

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, :ok, opts)
  end

  def init(:ok) do
    issuers = Application.get_env(:oauth2_metadata_updater, :issuers)

    children =
      [worker(Oauth2MetadataUpdater.Metadata, [])] ++
      [worker(Oauth2MetadataUpdater.Jwks, [])] ++
      Enum.map(issuers, fn({issuer, opts}) ->
        worker(Oauth2MetadataUpdater.Updater,
               [Keyword.put(init_properties(opts), :issuer, issuer)],
               id: issuer)
      end)

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp init_properties(issuer_config) do
    defaults = [
      refresh_interval: 60*60,
      well_known_path: "/.well-known/openid-configuration",
      resolve_jwks: true,
      allow_forced_refresh: true,
      forced_refresh_min_interval: 30
    ]

    Keyword.merge(defaults, issuer_config)
  end
end


