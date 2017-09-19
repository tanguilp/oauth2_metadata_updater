defmodule Oauth2MetadataUpdater.Supervisor do
  use Supervisor
  
  import Supervisor.Spec

  def start_link(opts) do
    Supervisor.start_link(__MODULE__, :ok, opts)
  end

  def init(:ok) do
    refresh_interval = Application.get_env(:oauth2_metadata_updater, :refresh_interval)
    targets = Application.get_env(:oauth2_metadata_updater, :targets)

    children =
      [worker(Oauth2MetadataUpdater.Metadata, [])] ++
      Enum.map(targets, fn({name, opts}) ->
        worker(Oauth2MetadataUpdater.Updater,
               [[name: name, target: opts[:url], refresh_interval: refresh_interval]],
               id: name)
      end)

    Supervisor.init(children, strategy: :one_for_one)
  end
end


