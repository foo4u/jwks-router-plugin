# JWKS Router Plugin Sample

**The code in this repository is experimental and has been provided for reference purposes only. Community feedback is welcome but this project may not be supported in the same way that repositories in the official [Apollo GraphQL GitHub organization](https://github.com/apollographql) are. If you need help you can file an issue on this repository, [contact Apollo](https://www.apollographql.com/contact-sales) to talk to an expert, or create a ticket directly in Apollo Studio.**

> Note: The Apollo Router is made available under the Elastic License v2.0 (ELv2).
> Read [our licensing page](https://www.apollographql.com/docs/resources/elastic-license-v2-faq/) for more details.

## Background

This project is a sample plugin to showcase how to implement [JSON Web Key Set (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517) support for Apollo Router to enable authentication. This plugin is **not meant for production** and is meant as a reference implementation. It has been tested using an Auth0 JWKS, but should work for any JWKS that uses RSA256 for JWT signing.

## Usage

To get started with the sample plugin, you'll need to first configure the `router.yaml` file with your specific settings. There are three configuration options, and only `jwks_url` is required. The configuration looks like:

```yml
plugins:
  example.jwks:
    # required
    jwks_url: "JWKS_URL_HERE"
    # default value
    token_header: "Authorization"
    # default value
    token_prefix: Bearer
```

## Usage from Your Router Repository

To this plugin from your own router repository, you'll need to include this
`jwks-router-plugin` as a dependency in your `Cargo.toml` file. Since this plugin
is not published to [crates.io](https://crates.io/), you can accomplish this using
a GitHub reference. For example:

```toml
[dependencies]
jwks-router-plugin = { git = "https://github.com/apollosolutions/jwks-router-plugin", branch="main" }
```

Then you'll need to register this plugin, which, can be done simply by adding it to your
`plugins/mod.rs` file. Suppose your company, Acme, wanted to use this plugin as `achme.jwks`,
rather than `example.jwks`, you'd simply add:

```rust
use apollo_router::register_plugin;
pub use jwks_router_plugin::plugins::jwks_plugin::JwksPlugin;

register_plugin!("acme", "jwks", JwksPlugin);
```

The prefix used when calling `register_plugin` is used below when configuring the plugin.
Now you can configure your `router.yaml` file with your JWKS settings. 
The configuration looks like:

```yml
plugins:
  acme.jwks:
    jwks_url: "JWKS_URL_HERE"
    token_header: "Authorization"
    token_prefix: Bearer
```

## Test the plugin with Apollo Router

During development it is convenient to use `cargo run` to run the Apollo Router as it will build via `cargo` directly without requiring building and executing.

```bash
cargo run -- --hot-reload --config router.yaml --supergraph supergraph-schema.graphql
```

> If you are using managed federation you can set APOLLO_KEY and APOLLO_GRAPH_REF environment variables instead of specifying the supergraph as a file.

## Compile the Router for Release

To create a debug build use the following command.

```bash
cargo build
```

Your debug binary is now located in `target/debug/router`

For production, you will want to create a release build.

```bash
cargo build --release
```

Your release binary is now located in `target/release/router`

## Licensing

Source code in this repository is covered by the Elastic License 2.0. The
default throughout the repository is a license under the Elastic License 2.0,
unless a file header or a license file in a subdirectory specifies another
license. [See the LICENSE](./LICENSE) for the full license text.
