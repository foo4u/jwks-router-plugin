# JWKS Router Plugin Sample

**The code in this repository is experimental and has been provided for reference purposes only. Community feedback is welcome but this project may not be supported in the same way that repositories in the official [Apollo GraphQL GitHub organization](https://github.com/apollographql) are. If you need help you can file an issue on this repository, [contact Apollo](https://www.apollographql.com/contact-sales) to talk to an expert, or create a ticket directly in Apollo Studio.**

> Note: The Apollo Router is made available under the Elastic License v2.0 (ELv2).
> Read [our licensing page](https://www.apollographql.com/docs/resources/elastic-license-v2-faq/) for more details.

## Background

This project is a sample plugin to showcase how to implement [JSON Web Key Set (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517) support for Apollo Router to enable authentication. This plugin is **not meant for production** and is meant as a reference implementation. It has been tested using an Auth0 JWKS, but should work for any JWKS that uses RSA256 for JWT signing.

## Usage

To get started with the sample plugin, you'll need to first configure the `router.yaml` file with your specific settings. There are three configuration options, and only one the `jwks_url` required:

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

By default, the plugin looks for an `Authorization` header and the token prefixed by `Bearer`. The plugin supports an optional empty prefix if you prefer to pass without it.

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
