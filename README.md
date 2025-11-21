ercgen
=====

An X.509 certificate generation utility for Erlang in Rust NIF.

## Usage

For Elixir, add `ercgen` as a dependency in your `mix.exs`:

```elixir
defp deps do
  [{:ercgen, "~> 0.1.0"}]
end
```

For Erlang, add `ercgen` to your Erlang application's dependencies in your `rebar.config`:

```erlang
{deps, [
  {ercgen, "0.1.0"}
]}.
```
## Supported Versions

- Erlang/OTP 27 and above
- Rust 1.89 and above

## Features

- `ercgen:signed_by/4`
  Generate an X.509 certificate signed by a given CA. Used for creating self-signed certificates.
- `ercgen:default_certificate_params/0`
  Provides default parameters for certificate generation.
- `ercgen:check_certificate_params/1`
  Validates the provided certificate parameters.
- `ercgen:generate_rsa_private_key/0`
  Generates a new RSA key pair.
- `ercgen:rsa_public_key_to_pem/1`
  Converts an RSA public key to PEM format.
- `ercgen:rsa_private_key_to_der/1`
  Converts an RSA private key to DER format.

## License

This project is licensed under the Apache-2.0 License. See the [LICENSE](LICENSE) file for details.
