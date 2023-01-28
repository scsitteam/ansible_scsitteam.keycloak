# -*- coding: utf-8 -*-

# Copyright (c) 2023, Marius Rieder <marius.rieder@scs.ch>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
from functools import cached_property
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import urlparse

from ansible_collections.scsitteam.keycloak.plugins.module_utils.api import KeycloakApi


class AnsibleKeycloakModule(AnsibleModule):
    def __init__(self, argument_spec, **kwargs):
        argument_spec.update(dict(
            keycloak_url=dict(type='str', required=True, no_log=False),
            keycloak_client_id=dict(type='str', default='admin-cli'),
            keycloak_realm=dict(type='str', default='master'),
            keycloak_client_secret=dict(type='str', default=None, no_log=True),
            keycloak_username=dict(type='str'),
            keycloak_password=dict(type='str', no_log=True),
            keycloak_token=dict(type='str', no_log=True),
            validate_certs=dict(type='bool', default=True),
            connection_timeout=dict(type='int', default=10),
        ))

        super().__init__(argument_spec,  **kwargs)

        if urlparse(self.params['keycloak_url']).scheme not in ['http', 'https']:
            self.fail_json(f"keycloak_url '{self.params['keycloak_url']}' should either start with 'http' or 'https'.")

    @cached_property
    def api(self):
        return KeycloakApi(self)