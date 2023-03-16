# -*- coding: utf-8 -*-

# Copyright (c) 2023, Marius Rieder <marius.rieder@scs.ch>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils.urls import Request
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils.six.moves.urllib.error import HTTPError

import json
from functools import cached_property


class KeycloakApi(object):
    def __init__(self, module):
        self.module = module

    def get(self, url):
        url = f"{self.module.params['keycloak_url']}/{ url }"
        try:
            return json.loads(self._cli.get(url).read())
        except HTTPError as e:
            data = json.loads(e.read())
            self.module.fail_json(f"Could not get {url}: {data}")
        except json.JSONDecodeError as e:
            self.module.fail_json(f"API returned invalid JSON when trying to get {url}: {str(e)}")
        except Exception as e:
            self.module.fail_json(f"Could not get {url}: {str(e)}")

    def post(self, url, payload):
        url = f"{self.module.params['keycloak_url']}/{ url }"
        try:
            data = self._cli.post(url, data=json.dumps(payload)).read()
            if data:
                return json.loads(data)
            return None
        except HTTPError as e:
            data = json.loads(e.read())
            self.module.fail_json(f"Could not post {url}: {data}")
        except json.JSONDecodeError as e:
            self.module.fail_json(f"API returned invalid JSON when trying to post {url}: {str(e)}")
        except Exception as e:
            self.module.fail_json(f"Could not post {url}: {str(e)}")

    def put(self, url, payload):
        url = f"{self.module.params['keycloak_url']}/{ url }"
        try:
            data = self._cli.put(url, data=json.dumps(payload)).read()
            if data:
                return json.loads(data)
            return None
        except HTTPError as e:
            data = json.loads(e.read())
            self.module.fail_json(f"Could not put {url}: {data}")
        except json.JSONDecodeError as e:
            self.module.fail_json(f"API returned invalid JSON when trying to put {url}: {str(e)}")
        except Exception as e:
            self.module.fail_json(f"Could not put {url}: {str(e)}")

    def delete(self, url):
        url = f"{self.module.params['keycloak_url']}/{ url }"
        try:
            data = self._cli.delete(url).read()
            if data:
                return json.loads(data)
            return None
        except HTTPError as e:
            data = json.loads(e.read())
            self.module.fail_json(f"Could not delete {url}: {data}")
        except json.JSONDecodeError as e:
            self.module.fail_json(f"API returned invalid JSON when trying to delete {url}: {str(e)}")
        except Exception as e:
            self.module.fail_json(f"Could not delete {url}: {str(e)}")

    @cached_property
    def _cli(self):
        cli = Request(
            timeout=self.module.params.get('connection_timeout'),
            validate_certs=self.module.params.get('validate_certs'),
            http_agent=f"Ansible-{self.module.ansible_version}/{self.module._name}"
        )

        payload = {
            'grant_type': 'password',
            'client_id': self.module.params.get('auth_client_id'),
            'username': self.module.params.get('auth_username'),
            'password': self.module.params.get('auth_password'),
        }

        try:
            token_url = f"{self.module.params['keycloak_url']}/realms/{self.module.params['auth_realm']}/protocol/openid-connect/token"
            data = json.loads(cli.post(token_url, data=urlencode(payload)).read())
        except HTTPError as e:
            data = json.loads(e.read())
            self.module.fail_json(f"Could not obtain access token from {token_url}: {data}")
        except ValueError as e:
            self.module.fail_json(f"API returned invalid JSON when trying to obtain access token from {token_url}: {str(e)}")
        except Exception as e:
            self.module.fail_json(f"Could not obtain access token from {token_url}: {str(e)}")

        cli.headers.update({
            'Authorization': f"Bearer {data['access_token']}",
            'Content-Type': 'application/json'
        })

        return cli
