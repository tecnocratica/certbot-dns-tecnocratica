"""DNS Authenticator for Tecnocratica (Neodigit/Virtualname)."""
import logging
import time
from typing import Any, Callable, Optional

import requests

from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

__all__ = ['Authenticator']

DEFAULT_API_URL = 'https://api.neodigit.net/v1'
DEFAULT_TIMEOUT = 30
MAX_RETRIES = 3
BACKOFF_FACTOR = 1  # seconds; sleeps 1, 2, 4 …


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Tecnocratica (Neodigit/Virtualname).

    This Authenticator uses the Neodigit/Virtualname API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record '
                   '(if you are using Tecnocratica/Neodigit/Virtualname for DNS).')

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None
        self._client: Optional['_TecnocraticaClient'] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 60) -> None:
        """Add plugin arguments to the CLI parser."""
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Tecnocratica credentials INI file.')

    def more_info(self) -> str:
        """Return more information about this plugin."""
        return ('This plugin configures a DNS TXT record to respond to a dns-01 challenge using '
                'the Neodigit/Virtualname API.')

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Tecnocratica credentials INI file',
            {
                'api-token': 'API token for Neodigit/Virtualname',
            },
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_client().del_txt_record(domain, validation_name, validation)

    def _get_client(self) -> '_TecnocraticaClient':
        if not self.credentials:
            raise errors.Error('Plugin has not been prepared.')
        if self._client is None:
            api_url = self.credentials.conf('api-url') or DEFAULT_API_URL
            self._client = _TecnocraticaClient(
                api_token=self.credentials.conf('api-token'),
                api_url=api_url,
            )
        return self._client


class _TecnocraticaClient:
    """Encapsulates all communication with the Neodigit/Virtualname API."""

    def __init__(self, api_token: str, api_url: str) -> None:
        self.session = requests.Session()
        self.session.headers.update({
            'X-TCpanel-Token': api_token,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        })
        self.api_url = api_url.rstrip('/')
        self._zones: Optional[list[dict[str, Any]]] = None

    @staticmethod
    def _format_error(action: str, resp: requests.Response) -> str:
        """Return a human-readable error message based on the HTTP status code."""
        code = resp.status_code
        if code in (401, 403):
            category = 'authentication failure'
        elif code == 429:
            category = 'rate limit exceeded'
        elif 500 <= code < 600:
            category = 'server error'
        else:
            category = 'request failed'
        return f'Error {action}: {category} ({code} {resp.text})'

    def _request_with_retry(self, method: str, url: str,
                            **kwargs: Any) -> requests.Response:
        """Execute an HTTP request with retry and exponential backoff.

        Retries on transient network errors (ConnectionError, Timeout) and
        HTTP 429 (rate-limit) responses up to ``MAX_RETRIES`` times.
        """
        kwargs.setdefault('timeout', DEFAULT_TIMEOUT)
        last_exception: Optional[Exception] = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = self.session.request(method, url, **kwargs)
                if resp.status_code != 429 or attempt == MAX_RETRIES:
                    return resp
                logger.debug('Rate-limited (429); retrying (%d/%d)…',
                             attempt + 1, MAX_RETRIES)
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exception = exc
                if attempt == MAX_RETRIES:
                    raise
                logger.debug('Transient error %s; retrying (%d/%d)…',
                             exc, attempt + 1, MAX_RETRIES)

            time.sleep(BACKOFF_FACTOR * (2 ** attempt))

        # Unreachable, but keeps mypy happy.
        raise requests.ConnectionError(str(last_exception))  # pragma: no cover

    def add_txt_record(self, domain: str, validation_name: str, validation: str) -> None:
        """Create a TXT record for the given domain and validation string."""
        zone_id, zone_name = self._find_zone(domain)

        record_name = self._relative_name(validation_name, zone_name)

        # Skip creation if an identical record already exists (idempotent).
        existing = self._find_record_id(zone_id, zone_name, validation_name, validation)
        if existing:
            logger.debug('TXT record already exists (id=%s); skipping creation.', existing)
            return

        data = {
            'record': {
                'name': record_name,
                'type': 'TXT',
                'content': validation,
                'ttl': 60,
            }
        }

        logger.debug('Adding TXT record to zone %s (id=%s): %s', zone_name, zone_id, data)
        resp = self._request_with_retry(
            'post',
            f'{self.api_url}/dns/zones/{zone_id}/records',
            json=data,
        )
        if not resp.ok:
            raise errors.PluginError(
                self._format_error('adding TXT record', resp)
            )
        logger.debug('Successfully added TXT record.')

    def del_txt_record(self, domain: str, validation_name: str, validation: str) -> None:
        """Delete the TXT record for the given domain and validation string."""
        try:
            zone_id, zone_name = self._find_zone(domain)
        except errors.PluginError as e:
            logger.debug('Could not find zone during cleanup: %s', e)
            return

        record_id = self._find_record_id(zone_id, zone_name, validation_name, validation)
        if not record_id:
            logger.debug('TXT record not found; no cleanup needed.')
            return

        try:
            logger.debug('Deleting TXT record %s from zone %s', record_id, zone_id)
            resp = self._request_with_retry(
                'delete',
                f'{self.api_url}/dns/zones/{zone_id}/records/{record_id}',
            )
            if not resp.ok:
                logger.warning('%s', self._format_error('deleting TXT record', resp))
            else:
                logger.debug('Successfully deleted TXT record.')
        except requests.RequestException as e:
            logger.warning('Error deleting TXT record: %s', e)

    def _find_zone(self, domain: str) -> tuple[int, str]:
        """Find the zone ID and name for the given domain."""
        zones = self._get_zones()
        domain_name_guesses = dns_common.base_domain_name_guesses(domain)

        for guess in domain_name_guesses:
            for zone in zones:
                try:
                    zone_name = (zone.get('human_name') or zone.get('name', '')).rstrip('.')
                    if zone_name.lower() == guess.lower():
                        return zone['id'], zone_name
                except (KeyError, AttributeError) as exc:
                    raise errors.PluginError(
                        f'Unexpected zone record structure: {zone!r}'
                    ) from exc

        raise errors.PluginError(
            f'Unable to find zone for {domain} using guesses: {domain_name_guesses}'
        )

    def _get_zones(self) -> list[dict[str, Any]]:
        """Fetch and cache the list of DNS zones."""
        if self._zones is not None:
            return self._zones

        try:
            resp = self._request_with_retry('get', f'{self.api_url}/dns/zones')
            resp.raise_for_status()
        except requests.RequestException as e:
            raise errors.PluginError(f'Error fetching DNS zones: {e}') from e

        data = resp.json()
        if not isinstance(data, list):
            raise errors.PluginError(
                f'Unexpected zones response: expected list, got {type(data).__name__}'
            )

        self._zones = data
        return self._zones

    def _find_record_id(self, zone_id: int, zone_name: str,
                        validation_name: str, validation: str) -> Optional[int]:
        """Find the record ID for a TXT record matching name and content."""
        try:
            resp = self._request_with_retry(
                'get',
                f'{self.api_url}/dns/zones/{zone_id}/records',
                params={'type': 'TXT'},
            )
            resp.raise_for_status()
        except requests.RequestException as e:
            logger.debug('Error fetching TXT records: %s', e)
            return None

        record_name = self._relative_name(validation_name, zone_name)

        for record in resp.json():
            try:
                if record['name'] == record_name and record['content'] == validation:
                    return record['id']
            except KeyError as exc:
                raise errors.PluginError(
                    f'Unexpected record structure: {record!r}'
                ) from exc

        return None

    @staticmethod
    def _relative_name(fqdn: str, zone_name: str) -> str:
        """Compute the record name relative to the zone.

        For example, if fqdn is '_acme-challenge.example.com' and zone is
        'example.com', returns '_acme-challenge'. If fqdn equals the zone,
        returns '@'.
        """
        fqdn = fqdn.rstrip('.')
        zone_name = zone_name.rstrip('.')
        suffix = '.' + zone_name
        if fqdn == zone_name:
            return '@'
        if fqdn.endswith(suffix):
            return fqdn[:-len(suffix)]
        return fqdn
