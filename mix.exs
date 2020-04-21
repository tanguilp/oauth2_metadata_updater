defmodule Oauth2MetadataUpdater.Mixfile do
  use Mix.Project

  def project do
    [
      app: :oauth2_metadata_updater,
      description: "OAuth2 and OpenID Connect metadata updater for Elixir",
      version: "0.2.0",
      elixir: "~> 1.5",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        main: "readme",
        extras: ["README.md"]
      ],
      package: package(),
      source_url: "https://github.com/tanguilp/oauth2_metadata_updater"
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
      {:content_type, "~> 0.1.0"},
      {:dialyxir, "~> 1.0.0-rc.4", only: [:dev], runtime: false},
      {:ex_doc, "~> 0.19", only: :dev, runtime: false},
      {:oauth2_utils, "~> 0.1.0"},
      {:tesla, "~> 1.3.0"}
    ]
  end

  def package() do
    [
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => "https://github.com/tanguilp/oauth2_metadata_updater"}
    ]
  end
end
