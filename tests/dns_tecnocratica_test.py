"""Tests for certbot_dns_tecnocratica.dns_tecnocratica."""
# pylint: disable=missing-function-docstring,protected-access,too-many-public-methods

import unittest
from unittest import mock

import requests

from certbot import errors
from certbot.compat import os
from certbot.plugins import dns_test_common
from certbot.plugins.dns_test_common import DOMAIN
from certbot.tests import util as test_util

from certbot_dns_tecnocratica.dns_tecnocratica import (
    Authenticator,
    DEFAULT_API_URL,
    MAX_RETRIES,
    _TecnocraticaClient,
)

API_TOKEN = 'fake-api-token'
API_URL = 'https://api.neodigit.net/v1'
CUSTOM_API_URL = 'https://api.virtualname.net/v1'

ZONE_ID = 42
ZONE_NAME = 'example.com'
RECORD_ID = 123


class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common.BaseAuthenticatorTest):
    """Tests for the Authenticator plugin."""

    def setUp(self):
        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {"dns_tecnocratica_api_token": API_TOKEN}, path)

        self.config = mock.MagicMock(
            dns_tecnocratica_credentials=path,
            dns_tecnocratica_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "dns-tecnocratica")

        self.mock_client = mock.MagicMock()
        self.auth._get_client = mock.MagicMock(return_value=self.mock_client)

    @test_util.patch_display_util()
    def test_perform(self, unused_mock_get_utility):
        self.auth.perform([self.achall])

        expected = [mock.call.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_cleanup(self):
        self.auth._attempt_cleanup = True
        self.auth.cleanup([self.achall])

        expected = [mock.call.del_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, mock.ANY)]
        self.assertEqual(expected, self.mock_client.mock_calls)

    def test_no_creds(self):
        dns_test_common.write({}, self.config.dns_tecnocratica_credentials)
        self.assertRaises(errors.PluginError,
                          self.auth.perform,
                          [self.achall])

    @test_util.patch_display_util()
    def test_client_is_cached(self, unused_mock_get_utility):
        """Verify _get_client returns the same instance on repeated calls."""
        auth = Authenticator(self.config, "dns-tecnocratica")
        auth._setup_credentials()
        client1 = auth._get_client()
        client2 = auth._get_client()
        self.assertIs(client1, client2)


class AuthenticatorCustomApiUrlTest(test_util.TempDirTestCase,
                                    dns_test_common.BaseAuthenticatorTest):
    """Test that a custom api-url from the credentials file is honoured."""

    def setUp(self):
        super().setUp()

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write(
            {
                "dns_tecnocratica_api_token": API_TOKEN,
                "dns_tecnocratica_api_url": CUSTOM_API_URL,
            },
            path,
        )

        self.config = mock.MagicMock(
            dns_tecnocratica_credentials=path,
            dns_tecnocratica_propagation_seconds=0)

        self.auth = Authenticator(self.config, "dns-tecnocratica")

    @test_util.patch_display_util()
    def test_custom_api_url(self, unused_mock_get_utility):
        self.auth._setup_credentials()
        client = self.auth._get_client()
        self.assertEqual(CUSTOM_API_URL, client.api_url)

    @test_util.patch_display_util()
    def test_default_api_url(self, unused_mock_get_utility):
        """When api-url is not set, the default URL is used."""
        # Rewrite credentials without the api-url key
        path = os.path.join(self.tempdir, 'default.ini')
        dns_test_common.write(
            {"dns_tecnocratica_api_token": API_TOKEN}, path)
        self.config.dns_tecnocratica_credentials = path

        auth = Authenticator(self.config, "dns-tecnocratica")
        auth._setup_credentials()

        client = auth._get_client()
        self.assertEqual(DEFAULT_API_URL, client.api_url)


class TecnocraticaClientTest(unittest.TestCase):
    """Tests for the _TecnocraticaClient API wrapper."""

    record_name = '_acme-challenge'
    record_content = 'fake-validation-token'
    zone_id = ZONE_ID
    zone_name = ZONE_NAME
    record_id = RECORD_ID

    def setUp(self):
        self.client = _TecnocraticaClient(
            api_token=API_TOKEN, api_url=API_URL)

        self.session = mock.MagicMock()
        self.client.session = self.session

    def _request_calls(self, method):
        """Return call_args entries for requests matching the given HTTP method."""
        return [c for c in self.session.request.call_args_list
                if c[0][0] == method]

    def _mock_zones_response(self, zones=None):
        """Set up a mock response for zone listing."""
        if zones is None:
            zones = [{'id': self.zone_id, 'human_name': self.zone_name}]
        resp = mock.MagicMock()
        resp.ok = True
        resp.json.return_value = zones
        resp.raise_for_status = mock.MagicMock()
        return resp

    def _mock_records_response(self, records=None):
        """Set up a mock response for record listing."""
        if records is None:
            records = [{'id': self.record_id, 'name': self.record_name,
                        'content': self.record_content}]
        resp = mock.MagicMock()
        resp.ok = True
        resp.json.return_value = records
        resp.raise_for_status = mock.MagicMock()
        return resp

    @staticmethod
    def _mock_ok_response():
        resp = mock.MagicMock()
        resp.ok = True
        return resp

    @staticmethod
    def _mock_error_response(status_code=400):
        resp = mock.MagicMock()
        resp.ok = False
        resp.status_code = status_code
        resp.text = 'Error'
        return resp

    def test_add_txt_record(self):
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])
        ok_resp = self._mock_ok_response()

        self.session.request.side_effect = [zones_resp, no_records_resp, ok_resp]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

        post_calls = self._request_calls('post')
        self.assertEqual(1, len(post_calls))
        call_args = post_calls[0]
        self.assertIn(f'/dns/zones/{self.zone_id}/records', call_args[0][1])

        post_data = call_args[1]['json']['record']
        self.assertEqual('TXT', post_data['type'])
        self.assertEqual(self.record_name, post_data['name'])
        self.assertEqual(self.record_content, post_data['content'])
        self.assertEqual(60, post_data['ttl'])

    def test_add_txt_record_already_exists(self):
        """When an identical record already exists, skip creation."""
        zones_resp = self._mock_zones_response()
        existing_records_resp = self._mock_records_response()

        self.session.request.side_effect = [zones_resp, existing_records_resp]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

        # POST should never be called
        self.assertEqual(0, len(self._request_calls('post')))

    def test_add_txt_record_error(self):
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])

        self.session.request.side_effect = [
            zones_resp, no_records_resp, self._mock_error_response()]

        self.assertRaises(
            errors.PluginError,
            self.client.add_txt_record,
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    def test_add_txt_record_error_during_zone_lookup(self):
        self.session.request.side_effect = requests.RequestException(
            'connection error')

        self.assertRaises(
            errors.PluginError,
            self.client.add_txt_record,
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    def test_add_txt_record_zone_not_found(self):
        self.session.request.return_value = self._mock_zones_response(zones=[])

        self.assertRaises(
            errors.PluginError,
            self.client.add_txt_record,
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    def test_del_txt_record(self):
        zones_resp = self._mock_zones_response()
        records_resp = self._mock_records_response()
        delete_resp = self._mock_ok_response()

        self.session.request.side_effect = [zones_resp, records_resp, delete_resp]

        self.client.del_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

        delete_calls = self._request_calls('delete')
        self.assertEqual(1, len(delete_calls))
        self.assertIn(
            f'/dns/zones/{self.zone_id}/records/{self.record_id}',
            delete_calls[0][0][1])

    def test_del_txt_record_error_during_zone_lookup(self):
        self.session.request.side_effect = requests.RequestException(
            'connection error')

        # Should not raise - cleanup is best-effort
        self.client.del_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    def test_del_txt_record_error_during_delete(self):
        zones_resp = self._mock_zones_response()
        records_resp = self._mock_records_response()

        self.session.request.side_effect = [
            zones_resp, records_resp, self._mock_error_response()]

        # Should not raise - cleanup is best-effort
        self.client.del_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    def test_del_txt_record_error_during_record_lookup(self):
        zones_resp = self._mock_zones_response()

        self.session.request.side_effect = [
            zones_resp, requests.RequestException('error')]

        # Should not raise - cleanup is best-effort
        self.client.del_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertEqual(0, len(self._request_calls('delete')))

    def test_del_txt_record_no_record(self):
        zones_resp = self._mock_zones_response()
        records_resp = self._mock_records_response(records=[])

        self.session.request.side_effect = [zones_resp, records_resp]

        # Should not raise and should not attempt delete
        self.client.del_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertEqual(0, len(self._request_calls('delete')))

    # --- Retry logic tests ---

    @mock.patch('certbot_dns_tecnocratica.dns_tecnocratica.time.sleep')
    def test_retry_on_connection_error(self, mock_sleep):
        """Transient ConnectionError is retried and succeeds."""
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])
        ok_resp = self._mock_ok_response()

        self.session.request.side_effect = [
            zones_resp, no_records_resp,
            requests.ConnectionError('reset'), ok_resp]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertEqual(2, len(self._request_calls('post')))
        mock_sleep.assert_called()

    @mock.patch('certbot_dns_tecnocratica.dns_tecnocratica.time.sleep')
    def test_retry_on_timeout(self, mock_sleep):
        """Transient Timeout is retried and succeeds."""
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])
        ok_resp = self._mock_ok_response()

        self.session.request.side_effect = [
            zones_resp, no_records_resp,
            requests.Timeout('timed out'), ok_resp]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertEqual(2, len(self._request_calls('post')))
        mock_sleep.assert_called()

    @mock.patch('certbot_dns_tecnocratica.dns_tecnocratica.time.sleep')
    def test_retry_on_429(self, mock_sleep):
        """HTTP 429 triggers retry; subsequent success is returned."""
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])

        rate_limited = mock.MagicMock()
        rate_limited.status_code = 429
        ok_resp = self._mock_ok_response()
        ok_resp.status_code = 200

        self.session.request.side_effect = [
            zones_resp, no_records_resp, rate_limited, ok_resp]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertEqual(2, len(self._request_calls('post')))
        mock_sleep.assert_called()

    @mock.patch('certbot_dns_tecnocratica.dns_tecnocratica.time.sleep')
    def test_retry_exhausted_raises(self, _mock_sleep):
        """All retries exhausted on ConnectionError re-raises."""
        self.session.request.side_effect = requests.ConnectionError('down')

        self.assertRaises(
            errors.PluginError,
            self.client.add_txt_record,
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    @mock.patch('certbot_dns_tecnocratica.dns_tecnocratica.time.sleep')
    def test_retry_backoff_timing(self, mock_sleep):
        """Verify exponential backoff sleep durations."""
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])
        ok_resp = self._mock_ok_response()
        ok_resp.status_code = 200

        self.session.request.side_effect = [
            zones_resp, no_records_resp,
            requests.ConnectionError('err'),
            requests.ConnectionError('err'),
            ok_resp,
        ]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

        # BACKOFF_FACTOR=1: sleeps 1*2^0=1, 1*2^1=2
        self.assertEqual(mock_sleep.call_args_list,
                         [mock.call(1), mock.call(2)])

    # --- API response validation tests ---

    def test_malformed_zones_response_not_list(self):
        """Non-list zones response raises PluginError."""
        resp = mock.MagicMock()
        resp.ok = True
        resp.json.return_value = {'error': 'unexpected'}
        resp.raise_for_status = mock.MagicMock()
        self.session.request.return_value = resp

        self.assertRaises(
            errors.PluginError,
            self.client.add_txt_record,
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    def test_malformed_zone_record_structure(self):
        """Zone entry without expected keys raises PluginError."""
        zones = [{'unexpected_field': 'value'}]
        zones_resp = self._mock_zones_response(zones=zones)
        self.session.request.return_value = zones_resp

        self.assertRaises(
            errors.PluginError,
            self.client.add_txt_record,
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    def test_malformed_record_structure(self):
        """Record entry missing required keys raises PluginError."""
        zones_resp = self._mock_zones_response()
        # Record missing 'name' and 'content' keys
        bad_records = [{'id': 999}]
        records_resp = self._mock_records_response(records=bad_records)

        self.session.request.side_effect = [zones_resp, records_resp]

        self.assertRaises(
            errors.PluginError,
            self.client.add_txt_record,
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)

    # --- Case-insensitive zone matching tests ---

    def test_find_zone_case_insensitive(self):
        """Zone matching is case-insensitive per RFC 4343."""
        zones = [{'id': self.zone_id, 'human_name': 'Example.COM'}]
        zones_resp = self._mock_zones_response(zones=zones)
        no_records_resp = self._mock_records_response(records=[])
        ok_resp = self._mock_ok_response()

        self.session.request.side_effect = [zones_resp, no_records_resp, ok_resp]

        # DOMAIN is 'example.com' — should match 'Example.COM'
        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertEqual(1, len(self._request_calls('post')))

    def test_find_zone_case_insensitive_name_field(self):
        """Case-insensitive matching works with the 'name' field too."""
        zones = [{'id': self.zone_id, 'name': 'EXAMPLE.COM.'}]
        zones_resp = self._mock_zones_response(zones=zones)
        no_records_resp = self._mock_records_response(records=[])
        ok_resp = self._mock_ok_response()

        self.session.request.side_effect = [zones_resp, no_records_resp, ok_resp]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertEqual(1, len(self._request_calls('post')))

    # --- Specific error message tests ---

    def test_error_message_auth_failure(self):
        """401/403 errors report authentication failure."""
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])
        self.session.request.side_effect = [
            zones_resp, no_records_resp,
            self._mock_error_response(status_code=401)]

        with self.assertRaises(errors.PluginError) as cm:
            self.client.add_txt_record(
                DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertIn('authentication failure', str(cm.exception))

    def test_error_message_rate_limit(self):
        """429 errors after exhausting retries report rate limit."""
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])

        rate_resp = self._mock_error_response(status_code=429)
        rate_resp.status_code = 429

        self.session.request.side_effect = (
            [zones_resp, no_records_resp] + [rate_resp] * (MAX_RETRIES + 1))

        with mock.patch(
                'certbot_dns_tecnocratica.dns_tecnocratica.time.sleep'):
            with self.assertRaises(errors.PluginError) as cm:
                self.client.add_txt_record(
                    DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertIn('rate limit exceeded', str(cm.exception))
        # Should have retried MAX_RETRIES + 1 times total
        self.assertEqual(MAX_RETRIES + 1, len(self._request_calls('post')))

    def test_error_message_server_error(self):
        """5xx errors report server error."""
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])
        self.session.request.side_effect = [
            zones_resp, no_records_resp,
            self._mock_error_response(status_code=500)]

        with self.assertRaises(errors.PluginError) as cm:
            self.client.add_txt_record(
                DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertIn('server error', str(cm.exception))

    def test_error_message_generic(self):
        """Non-categorized status codes report generic failure."""
        zones_resp = self._mock_zones_response()
        no_records_resp = self._mock_records_response(records=[])
        self.session.request.side_effect = [
            zones_resp, no_records_resp,
            self._mock_error_response(status_code=400)]

        with self.assertRaises(errors.PluginError) as cm:
            self.client.add_txt_record(
                DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.assertIn('request failed', str(cm.exception))

    def test_zone_list_is_cached(self):
        """Verify that _get_zones only fetches once."""
        zones_resp = self._mock_zones_response()
        no_records_resp1 = self._mock_records_response(records=[])
        no_records_resp2 = self._mock_records_response(records=[])
        ok_resp = self._mock_ok_response()

        self.session.request.side_effect = [
            zones_resp, no_records_resp1, ok_resp,
            no_records_resp2, ok_resp,
        ]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, self.record_content)
        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, 'other-token')

        # The zone endpoint should only have been called once
        zone_calls = [
            c for c in self.session.request.call_args_list
            if '/dns/zones' in c[0][1] and 'records' not in c[0][1]
        ]
        self.assertEqual(1, len(zone_calls))

    def test_relative_name(self):
        self.assertEqual(
            '_acme-challenge',
            _TecnocraticaClient._relative_name(
                '_acme-challenge.example.com', 'example.com'))
        self.assertEqual(
            '@',
            _TecnocraticaClient._relative_name(
                'example.com', 'example.com'))
        self.assertEqual(
            '_acme-challenge',
            _TecnocraticaClient._relative_name(
                '_acme-challenge.example.com.', 'example.com.'))
        self.assertEqual(
            'sub.domain',
            _TecnocraticaClient._relative_name(
                'sub.domain.example.com', 'example.com'))

    # --- Multi-record tests (wildcard cert scenario) ---

    def test_add_multiple_txt_records_same_zone(self):
        """Multiple TXT records can be created in the same zone (e.g. wildcard certs)."""
        zones_resp = self._mock_zones_response()
        no_records_resp1 = self._mock_records_response(records=[])
        no_records_resp2 = self._mock_records_response(records=[])
        ok_resp = self._mock_ok_response()

        self.session.request.side_effect = [
            zones_resp, no_records_resp1, ok_resp,
            no_records_resp2, ok_resp,
        ]

        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, 'token-1')
        self.client.add_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, 'token-2')

        self.assertEqual(2, len(self._request_calls('post')))

    def test_del_multiple_txt_records_same_zone(self):
        """Multiple TXT records can be cleaned up from the same zone."""
        zones_resp = self._mock_zones_response()
        records_resp1 = self._mock_records_response(
            records=[{'id': 101, 'name': self.record_name,
                       'content': 'token-1'}])
        records_resp2 = self._mock_records_response(
            records=[{'id': 102, 'name': self.record_name,
                       'content': 'token-2'}])
        ok_resp = self._mock_ok_response()

        self.session.request.side_effect = [
            zones_resp, records_resp1, ok_resp,
            records_resp2, ok_resp,
        ]

        self.client.del_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, 'token-1')
        self.client.del_txt_record(
            DOMAIN, '_acme-challenge.' + DOMAIN, 'token-2')

        delete_calls = self._request_calls('delete')
        self.assertEqual(2, len(delete_calls))
        delete_urls = [c[0][1] for c in delete_calls]
        self.assertIn(f'/dns/zones/{self.zone_id}/records/101', delete_urls[0])
        self.assertIn(f'/dns/zones/{self.zone_id}/records/102', delete_urls[1])


if __name__ == '__main__':
    unittest.main()  # pragma: no cover
