#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2023, Tom Bosmans tom.bosmans@be.ibm.com
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
name: tombosmansibm.pleasant_lookup.password
author: Tom Bosmans
version_added: "1.0.0"
short_description: lookup passwords in Pleasant Password server.
description:
    - Returns the content of the URL requested to be used as data in play.
    - This is using Python Requests https://docs.python-requests.org/en/latest/api/
options:
  _terms:
    description: Pleasant password server url.  This will be removed in a future version.
  pleasant_host:
    description: Pleasant password server url. Use instead of the positional argument.
    type: string
    version_added: "1.1.0"
    vars:
      - name: pleasant_host
    env:
      - name: PLEASANT_HOST
    ini:
      - section: pleasant_lookup
        key: host
  pleasant_api_version:
    description: Version of the api.  Only v5 or v6.
    type: string
    default: "v5"
    choices:
      - v5
      - v6
      - v7
    vars:
      - name: pleasant_api_version
    env:
      - name: PLEASANT_API_VERSION
    ini:
      - section: pleasant_lookup
        key: api_version
    version_added: "1.1.0"
  pleasant_search:
    description: Item name to search
    type: string
    default: null
  pleasant_filter_path:
    description: Limit to path.  A path starts with Root/
    type: string
  pleasant_filter_username:
    description: Limit to this username
    type: string
  verify:
    description: Flag to control SSL certificate validation.  The path to a ca bundle ( eg. /etc/ssl/certs/ca-bundle.crt ) or true/false
    default: true
    vars:
      - name: pleasant_lookup_ca_path
    env:
      - name: PLEASANT_LOOKUP_CA_PATH
    ini:
      - section: pleasant_lookup
        key: ca_path
  username:
    description: Username to authenticate to Pleasant
    type: string
    vars:
      - name: username
    env:
      - name: PLEASANT_USERNAME
    ini:
      - section: pleasant_lookup
        key: username
  password:
    description: Password to authenticate to Pleasant
    type: string
    vars:
      - name: password
    env:
      - name: PLEASANT_PASSWORD
    ini:
      - section: pleasant_lookup
        key: password
  headers:
    description: HTTP request headers
    type: dictionary
    default: {Content-Type: application/json}
    version_added: "1.0.5"
  force:
    description: Whether or not to set "cache-control" header with value "no-cache"
    type: boolean
    default: False
  timeout:
    description: How long to wait for the server to send data before giving up
    type: float
    default: 5
    vars:
      - name: pleasant_lookup_timeout
    env:
      - name: PLEASANT_LOOKUP_TIMEOUT
    ini:
      - section: pleasant_lookup
        key: timeout
"""

EXAMPLES = """

- name: password
  debug: msg="{{ lookup('tombosmansibm.pleasant_lookup.password', pleasant_host='https://pleasant.com:10001',
                          username='bob', password='hunter2', pleasant_search='itemname') }}"

# lookup example with search parameter and filter on username and path, with reference to the ca bundle of the system.
- name: Lookup
  run_once: True
  debug:
    msg: "{{ lookup('tombosmansibm.pleasant_lookup.password', pleasant_host='https://pleasant.com:10001',
       username='myuser', password='mypassword', pleasant_filter_path='Root/DEV/',
       pleasant_filter_username='root', pleasant_search='root', verify='/etc/ssl/certs/ca-bundle.crt', timeout=2) }}"
  delegate_to: localhost

The result is a list of items:
        [{
            "password": "the password",
            "path": "Root/Path/",
            "username": "the username"
        }]

"""

RETURN = """
_list:
  description: list of password objects containing username, password, path
  type: list
  elements: dict
"""

from ansible.errors import AnsibleError
import requests
from ansible.module_utils._text import to_text, to_native
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
# from ansible.module_utils.urls import open_url, ConnectionError, SSLValidationError

from urllib.parse import urljoin

display = Display()


class LookupModule(LookupBase):
    def get_token(self, pleasant_host, _pusername, _ppassword):
        verify = self.get_option('verify')
        if verify in ["false", "False", "FALSE"]:
            verify = False
        display.vv(f"Verify: {verify}")
        timeout = self.get_option('timeout')

        # get the access token from Pleasant
        try:
            payload = {"grant_type": "password", "username": _pusername, "password": _ppassword}
            # display.display("Payload: %s" % payload)
            response = requests.request("POST", urljoin(pleasant_host, "/oauth2/token"),
                                        data=payload, verify=verify, timeout=timeout)
            # response = open_url(urljoin(pleasant_host, "/oauth2/token"),
            #                    method="POST",
            #                    data=payload,
            #                    validate_certs=verify,
            #                    ca_path=ca_path,
            #                    timeout=timeout)
            if response.status_code != 200:
                # error
                display.display("Authentication failed getting an access token from Pleasant %s %s" % (
                    response.status_code, response.reason))
                response.raise_for_status()
        except requests.ConnectionError as e:
            raise AnsibleError("can't connect to host to get token %s" % to_native(e))
        except requests.HTTPError as e:
            raise AnsibleError("An HTTP Error occured %s" % to_native(e))
        except requests.URLRequired as e:
            raise AnsibleError("Invalid url %s" % to_native(e))
        except requests.ConnectTimeout as e:
            raise AnsibleError(
                "The request timed out while trying to connect to the remote server.  Retry later. %s" % to_native(e))
        except requests.Timeout as e:
            raise AnsibleError("The request timed out %s" % to_native(e))
        # parse the response
        try:
            _at = response.json()
        except Exception as e:
            raise AnsibleError("can't decode access token : %s , %s" % (_at, to_native(e)))
        return _at

    def search(self, pleasant_host, pleasant_search, _at):
        headers = {"Content-type": "application/json", "Authorization": "Bearer " + _at}
        payload = {"Search": pleasant_search}
        verify = self.get_option('verify')
        if verify in ["false", "False", "FALSE"]:
            verify = False
        timeout = self.get_option('timeout')

        try:
            response = requests.request("POST", urljoin(pleasant_host,
                                                        f"/api/{self.get_option('pleasant_api_version')}/rest/search"),
                                        headers=headers,
                                        json=payload, verify=verify, timeout=timeout)
            if response.status_code != 200:
                # error
                display.display("Search failed for this item: %s (%s %s)" % (
                    pleasant_search, response.status_code, response.reason))
                response.raise_for_status()
        except requests.ConnectionError as e:
            raise AnsibleError("can't connect to host to get token %s" % to_native(e))
        except requests.HTTPError as e:
            raise AnsibleError("An HTTP Error occured %s" % to_native(e))
        except requests.URLRequired as e:
            raise AnsibleError("Invalid url %s" % to_native(e))
        except requests.ConnectTimeout as e:
            raise AnsibleError(
                "The request timed out while trying to connect to the remote server.  Retry later. %s" % to_native(e))
        except requests.Timeout as e:
            raise AnsibleError("The request timed out %s" % to_native(e))
        except Exception as e:
            raise AnsibleError("Failed to execute search %s - error %s" % (pleasant_search, to_native(e)))
        return response

    def get_password(self, pleasant_host, pleasant_id, _at):
        #     url: "{{ pleasant_host }}/api/v5/rest/entries/{{ _pleasant_searchresult.json.Credentials[0].Id }}/attachments"
        # ethod: GET
        # headers:
        #  Content-Type: application/json
        #  Authorization: "Bearer {{ _pleasant_at.json.access_token }}"
        headers = {"Content-type": "application/json", "Authorization": "Bearer " + _at}
        verify = self.get_option('verify')
        if verify in ["false", "False", "FALSE"]:
            verify = False
        timeout = self.get_option('timeout')
        try:
            response = requests.request("GET", urljoin(pleasant_host,
                                                       f"/api/{self.get_option('pleasant_api_version')}/rest/entries/{pleasant_id}/password"),
                                        headers=headers,
                                        verify=verify, timeout=timeout)
            if response.status_code != 200:
                # error
                response.raise_for_status()
        except requests.ConnectionError as e:
            raise AnsibleError("can't connect to host to get token %s" % to_native(e))
        except requests.HTTPError as e:
            raise AnsibleError("An HTTP Error occured %s" % to_native(e))
        except requests.URLRequired as e:
            raise AnsibleError("Invalid url %s" % to_native(e))
        except requests.ConnectTimeout as e:
            raise AnsibleError(
                "The request timed out while trying to connect to the remote server.  Retry later. %s" % to_native(e))
        except requests.Timeout as e:
            raise AnsibleError("The request timed out %s" % to_native(e))
        except Exception as e:
            raise AnsibleError("Failed to get password %s - error %s" % (pleasant_id, to_native(e)))
        return response

    def run(self, terms, variables=None, **kwargs):
        display.v("New version")
        self.set_options(var_options=variables, direct=kwargs)

        ret = []
        pleasant_host = self.get_option('pleasant_host')
        if pleasant_host is None:
            for term in terms:
                display.vvv("Host: %s" % term)
                pleasant_host = term

        username = self.get_option('username')
        password = self.get_option('password')
        pleasant_search = self.get_option('pleasant_search')
        pleasant_filter_path = self.get_option('pleasant_filter_path')
        pleasant_filter_username = self.get_option('pleasant_filter_username')
        display.vvv("Filter path is %s" % pleasant_filter_path)
        # raise AnsibleError("term %s, username %s, password %s" % (term, username, password))
        # get access token
        at = self.get_token(pleasant_host, username, password)
        try:
            access_token = at.get('access_token', 'default')

            # perform search
            pitem = self.search(pleasant_host=pleasant_host, pleasant_search=pleasant_search, _at=access_token)
            if pitem.status_code == 200:
                # continue
                # retrieve item
                itemjson = pitem.json()
                display.vvvvvv(itemjson)
                ids = itemjson.get('Credentials')

                for entry in ids:
                    id = entry.get('Id')
                    idusername = entry.get('Username')
                    idpath = entry.get('Path')
                    performGet = False
                    display.vvvv("----------------------------------------")
                    display.vvvv("username: %s, path: %s" % (idusername, idpath))
                    if not pleasant_filter_username:
                        performGet = True
                    elif idusername == pleasant_filter_username:
                        performGet = True

                    if not pleasant_filter_path:
                        performGet = (True and performGet)
                    elif idpath.startswith(pleasant_filter_path):
                        performGet = (True and performGet)
                    else:
                        performGet = False

                    if bool(performGet):
                        display.v("Adding username: %s, path: %s" % (idusername, idpath))
                        r = self.get_password(pleasant_host=pleasant_host, pleasant_id=id, _at=access_token)
                        ret.append(
                            {"username": to_text(idusername), "password": to_text(r.json()), "path": to_text(idpath)})
            elif pitem.status_code == 401 or pitem.status_code == 403:
                # Not authenticated/not authorized
                pitem.raise_for_status()
            else:
                raise AnsibleError(
                    "Did not find %s (HTTP ERROR %s) on %s" % (pleasant_search, pitem.status_code, pleasant_host))
        except requests.ConnectionError as e:
            raise AnsibleError("Can't connect to host to get token %s" % to_native(e))
        except requests.HTTPError as e:
            raise AnsibleError("An HTTP Error occured %s" % to_native(e))
        except requests.URLRequired as e:
            raise AnsibleError("Invalid url : %s" % to_native(e))
        except requests.ConnectTimeout as e:
            raise AnsibleError(
                "The request timed out while trying to connect to the remote server.  Retry later: %s" % to_native(
                    e))
        except requests.Timeout as e:
            raise AnsibleError("The request timed out : %s" % to_native(e))
        except Exception as e:
            raise AnsibleError("No search result %s" % to_native(e))
        return ret
