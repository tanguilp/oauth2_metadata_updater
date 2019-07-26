defmodule Oauth2MetadataUpdater.Mixfile do
  use Mix.Project

  def project do
    [
      app: :oauth2_metadata_updater,
      version: "0.2.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Docs
      source_url: "https://github.com/tanguilp/oauth2_metadata_updater",
      docs: [extras: ["README.md"]]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger],
      mod: {Oauth2MetadataUpdater, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:httpoison, "~> 1.5"},
      {:poison, "~> 4.0"},
      {:oauth2_utils, github: "tanguilp/oauth2_utils", tag: "master"},
      {:content_type, github: "marcelotto/content_type", tag: "master"},
      {:bypass, github: "tanguilp/bypass-1", only: :test, tag: "master"},
      {:plug_cowboy, "~> 2.0", only: :test},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false}
    ]
  end
end
