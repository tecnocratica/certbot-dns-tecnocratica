# certbot-dns-tecnocratica

Certbot DNS authenticator plugin for [Tecnocratica](https://www.tecnocratica.net/) (Neodigit/Virtualname) DNS API.

Automates `dns-01` challenges by creating and removing TXT records via the [Neodigit](https://api.neodigit.net)/[Virtualname](https://api.virtualname.net) API.

## Installation

```bash
pip install certbot-dns-tecnocratica
```

Or for development:

```bash
pip install -e .
```

Verify the plugin is detected:

```bash
certbot plugins
```

## Credentials

Create a credentials file (e.g. `~/.secrets/certbot/tecnocratica.ini`):

```ini
dns_tecnocratica_api_token = your_api_token_here
```

Optionally override the API base URL (defaults to `https://api.neodigit.net/v1`):

```ini
dns_tecnocratica_api_token = your_api_token_here
dns_tecnocratica_api_url = https://api.virtualname.net/v1
```

Restrict permissions:

```bash
chmod 600 ~/.secrets/certbot/tecnocratica.ini
```

## Usage

```bash
certbot certonly \
  --authenticator dns-tecnocratica \
  --dns-tecnocratica-credentials ~/.secrets/certbot/tecnocratica.ini \
  -d example.com
```

### Wildcard certificate

```bash
certbot certonly \
  --authenticator dns-tecnocratica \
  --dns-tecnocratica-credentials ~/.secrets/certbot/tecnocratica.ini \
  -d example.com \
  -d "*.example.com"
```

### Custom propagation wait

```bash
certbot certonly \
  --authenticator dns-tecnocratica \
  --dns-tecnocratica-credentials ~/.secrets/certbot/tecnocratica.ini \
  --dns-tecnocratica-propagation-seconds 120 \
  -d example.com
```

### Test with Let's Encrypt staging

```bash
certbot certonly \
  --authenticator dns-tecnocratica \
  --dns-tecnocratica-credentials ~/.secrets/certbot/tecnocratica.ini \
  --dns-tecnocratica-propagation-seconds 60 \
  --server https://acme-staging-v02.api.letsencrypt.org/directory \
  --dry-run \
  -d example.com
```

## Testing

```bash
python -m pytest tests/
```

Run a single test:

```bash
python -m pytest tests/dns_tecnocratica_test.py::TecnocraticaClientTest::test_add_txt_record
```

## Security Notes

The credentials file should always be restricted (`chmod 600`). Be aware that
enabling debug-level logging for the `requests` or `urllib3` loggers will cause
HTTP headers -- including the API token -- to appear in log output. Avoid
shipping debug logs to shared or public destinations.

## Arguments

| Flag                                     | Description                         | Default    |
| ---------------------------------------- | ----------------------------------- | ---------- |
| `--dns-tecnocratica-credentials`         | Path to credentials INI file        | (required) |
| `--dns-tecnocratica-propagation-seconds` | Seconds to wait for DNS propagation | 60         |
