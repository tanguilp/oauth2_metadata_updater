defmodule Oauth2MetadataUpdater do
  use Application

  def start(_type, _args) do
    Oauth2MetadataUpdater.Supervisor.start_link(name: Oauth2MetadataUpdater.Supervisor)
  end
end
