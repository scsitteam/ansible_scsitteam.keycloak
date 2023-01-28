# -*- coding: utf-8 -*-

# Copyright (c) 2023, Marius Rieder <marius.rieder@scs.ch>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    # Standard documentation fragment
    DOCUMENTATION = r'''
options:
    keycloak_url:
        description:
            - URL to the Keycloak instance.
        type: str
        required: true
        aliases:
          - url

    keycloak_client_id:
        description:
            - OpenID Connect I(client_id) to authenticate to the API with.
        type: str
        default: admin-cli

    keycloak_realm:
        description:
            - Keycloak realm name to authenticate to for API access.
        type: str

    keycloak_client_secret:
        description:
            - Client Secret to use in conjunction with I(keycloak_client_id) (if required).
        type: str

    keycloak_username:
        description:
            - Username to authenticate for API access with.
        type: str

    keycloak_password:
        description:
            - Password to authenticate for API access with.
        type: str

    keycloak_token:
        description:
            - Authentication token for Keycloak API.
        type: str

    validate_certs:
        description:
            - Verify TLS certificates (do not disable this in production).
        type: bool
        default: true

    connection_timeout:
        description:
            - Controls the HTTP connections timeout period (in seconds) to Keycloak API.
        type: int
        default: 10
'''