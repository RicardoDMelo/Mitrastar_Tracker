"""

Support for MitraStar GPT-2541GNAC Router.
For more details about this platform, please refer to the documentation at
https://github.com/RicardoDMelo/MitraStar_GPT-2541GNAC_HA

"""
import base64
import logging
import re
import requests
import voluptuous as vol
import hashlib
from http.cookies import SimpleCookie

from homeassistant.components.device_tracker import (DOMAIN, PLATFORM_SCHEMA, DeviceScanner)
from homeassistant.const import (CONF_HOST, CONF_PASSWORD, CONF_USERNAME)
import homeassistant.helpers.config_validation as cv

_LOGGER = logging.getLogger(__name__)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend({
    vol.Required(CONF_HOST): cv.string,
    vol.Required(CONF_PASSWORD): cv.string,
    vol.Required(CONF_USERNAME): cv.string
})


def get_scanner(hass, config):
    """Validate the configuration and return an Actiontec scanner."""
    scanner = MitraStarDeviceScanner(config[DOMAIN])
    return scanner if scanner.success_init else None


class MitraStarDeviceScanner(DeviceScanner):
    """This class queries a MitraStar GPT-2541GNAC wireless Router."""

    def get_extra_attributes(self, device: str) -> dict:
        pass

    def __init__(self, config):
        """Initialize the scanner."""
        host = config[CONF_HOST]
        username = config[CONF_USERNAME]
        password = config[CONF_PASSWORD]

        self.parse_macs = re.compile(
            r'([0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2}:' + '[0-9a-fA-F]{2})')
        self.parse_dhcp = re.compile(
            r'<td>([0-9a-zA-Z\-._]+)</td><td>([0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})</td><td>([0-9]+.[0-9]+.[0-9]+.[0-9]+.[0-9]+)')

        self.host = host
        self.username = username
        self.password = password

        self.LOGIN_URL = 'http://{ip}/login-login.cgi'.format(**{'ip': self.host})
        self.headers1 = {
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36',
            'referer': 'http://192.168.15.1/login_frame.html',
            'content-type': 'application/x-www-form-urlencoded',
            'DNT': '1',
            'Upgrade-Insecure-Requests': '1',
            'Host': '192.168.15.1',
            'Origin': 'http://192.168.15.1'
        }

        self.last_results = {}
        self.hostnames = {}
        self.success_init = self._update_info()

    def scan_devices(self):
        """Scan for new devices and return a list with found device IDs."""
        self._update_info()
        return self.last_results

    def get_device_name(self, device):
        """This router doesn't save the name of the wireless device."""
        match = [element[0] for element in self.hostnames if element[1].lower() == device]
        if len(match) > 0:
            device_name = match[0]
        else:
            device_name = None
        return device_name

    def _update_info(self):
        """Ensure the information from the MitraStar router is up to date.
        Return boolean if scanning successful.
        """
        _LOGGER.info('Checking MitraStar GPT-2541GNAC Router')

        data, hostnames = self.get_mitrastar_info()
        if not data:
            return False

        self.last_results = data
        self.hostnames = hostnames
        return True

    def _read_table(self, session, url):
        response = session.get(url, headers=self.headers1)
        if response.status_code == 200:
            response_string = str(response.content, "utf-8")
            return response_string
        else:
            _LOGGER.warning(
                'Error trying to connect to url: {status} {url}'.format(**{'url': url, 'status': response.status_code}))
            return ''

    def get_mitrastar_info(self):
        """Retrieve data from MitraStar GPT-2541GNAC Router."""

        username1 = str(self.username)
        password1 = str(self.password)
        sid = '26db0ff7'
        text_to_hash = '{0}:{1}'.format(sid, password1)
        md5_hash = hashlib.md5(text_to_hash.encode('utf-8'))
        hashed_pwd = md5_hash.hexdigest()

        session_key = base64.b64encode(
            '{user}:{pass}'.format(**{
                'user': username1,
                'pass': hashed_pwd
            }).encode()
        )
        data1 = {
            'sessionKey': session_key,
            'user': username1,
            'pass': ''
        }

        session1 = requests.Session()
        login_response = session1.post(self.LOGIN_URL, data=data1, headers=self.headers1)

        if login_response.status_code == 200:
            cookies = SimpleCookie(login_response.headers['Set-Cookie'])
            session1.cookies.set("SESSION", cookies["SESSION"].value, domain=self.host)

            _LOGGER.info('Session cookie {session}'.format(**{'session': cookies["SESSION"].value}))

            url1 = 'http://{}/wlextstationlist.cmd?action=view&wlSsidIdx=2'.format(self.host)
            url2 = 'http://{}/wlextstationlist.cmd?action=view&wlSsidIdx=1'.format(self.host)
            url3 = 'http://{}/arpview.cmd'.format(self.host)
            url4 = 'http://{}/dhcpinfo.html'.format(self.host)

            result1 = self._read_table(session1, url1).lower()
            mac_address1 = self.parse_macs.findall(result1)

            result2 = self._read_table(session1, url2).lower()
            mac_address2 = self.parse_macs.findall(result2)

            result3 = self._read_table(session1, url3).lower()
            mac_address3 = self.parse_macs.findall(result3)

            result4 = self._read_table(session1, url4)
            result4 = result4.replace('\n ', '').replace(' ', '')
            hostnames = self.parse_dhcp.findall(result4)

            mac_address1.extend([element for element in mac_address2 if element not in mac_address1])
            mac_address1.extend([element for element in mac_address3 if element not in mac_address1])
            _LOGGER.info('MitraStar GPT-2541GNAC Router: Found %d devices' % len(mac_address1))

        else:
            mac_address1 = None
            hostnames = None
            _LOGGER.error('Error connecting to the router...')

        return mac_address1, hostnames
