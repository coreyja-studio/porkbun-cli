![Porkbun CLI Header](header.png)

# porkbun-cli

A Rust CLI for interacting with the [Porkbun](https://porkbun.com) DNS API.

## Features

- DNS record management (list, create, update, delete)
- SSL certificate retrieval
- Domain pricing information
- API ping/health check

## Installation

```bash
cargo install --path .
```

## Usage

```bash
# Check API connectivity
porkbun-cli ping

# List DNS records for a domain
porkbun-cli dns list example.com

# Create a new DNS record
porkbun-cli dns create example.com --type A --name www --content 192.168.1.1

# Delete a DNS record
porkbun-cli dns delete example.com <record-id>

# Get SSL certificate bundle
porkbun-cli ssl get example.com

# Get domain pricing
porkbun-cli pricing
```

## Configuration

The CLI reads API credentials from the `porkbun-api` secret via `mnemon secrets`:

- `api-key` - Your Porkbun API key
- `secret-key` - Your Porkbun secret API key

## License

MIT
