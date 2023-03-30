# Copyright: (c) 2023, Marius Rieder <marius.rieder@scs.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: authentication_password_policy

short_description: Manage Keycloak password policy via Keycloak API

version_added: "20.0.0"

description:
    - This module allows the administration of Keycloak password policy via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

options:
    policy:
        description:
            - Policies to manage as a dictionary with the policy name as keys and the policy config as value.
        type: dict
        suboptions:
            length:
                description: Minimal password length.
                type: int
            maxLength:
                description: Maximal password length.
                type: int
            lowerCase:
                description: Minimal number of lower case letters.
                type: int
            upperCase:
                description: Minimal number of upper case letters.
                type: int
            specialChars:
                description: Minimal number of special characters.
                type: int
            digits:
                description: Minimal number of digits.
                type: int
            regexPattern:
                description: Regexpattern the password must match.
                type: str
            notEmail:
                description: If the email address can not be used in the password.
                type: bool
            notUsername:
                description: If the username can not be used in the password.
                type: bool
            hashAlgorithm:
                description: Hash algorithm to use for hashing.
                type: str
            hashIterations:
                description: Number of hash interations to apply.
                type: int
            passwordHistory:
                description: Prevents a recently used password from being reused. How many to remember.
                type: int
            forceExpiredPasswordChange:
                description: The number of days the password is valid before a new password is required
                type: int
            passwordBlacklist:
                description: Prevents the use of a password that is in a blacklist file.
                type: str

    state:
        description:
            - State of the password policy
            - On C(present), the give policies will be enabled and configured.
            - On C(absent), the give policies will be deactivated.
            - On C(pure), the give policies will be enabled and configured. All other policies will be deactivated.
        choices: ['present', 'absent', 'pure']
        default: 'present'
        type: str

extends_documentation_fragment:
- scsitteam.keycloak.keycloak
author:
    - Marius Rieder (@jiuka)
'''

EXAMPLES = r'''
- name: Require at lease one digit
  scsitteam.kaycloak.authentication_password_policy:
    state: present
    policy:
      digits: 1

- name: Do not Require lower case characters
  scsitteam.kaycloak.authentication_password_policy:
    state: absent
    policy:
      lowerCase: 0

- name: Require only lower and upper case characters
  scsitteam.kaycloak.authentication_required_action:
    state: pure
    policy:
      lowerCase: 1
      upperCase: 1
'''

RETURN = r'''
required_action:
  description: Representation of the required action
  returned: success
  type: dict
  sample:
    {
      "alias": "VERIFY_PROFILE",
      "config": {},
      "defaultAction": false,
      "enabled": false,
      "name": "Verify Profile",
      "priority": 1001,
      "providerId": "VERIFY_PROFILE"
    }
'''

from ansible_collections.scsitteam.keycloak.plugins.module_utils.module import AnsibleKeycloakModule


def main():
    """
    Module execution

    :return:
    """
    argument_spec = dict(
        policy=dict(type='dict', default={}, options=dict(
            length=dict(type=int),
            maxLength=dict(type=int),
            lowerCase=dict(type=int),
            upperCase=dict(type=int),
            specialChars=dict(type=int),
            digits=dict(type=int),
            regexPattern=dict(type=str),
            notEmail=dict(type=bool),
            notUsername=dict(type=bool),
            hashAlgorithm=dict(type=str),
            hashIterations=dict(type=int),
            passwordHistory=dict(type=int),
            forceExpiredPasswordChange=dict(type=int),
            passwordBlacklist=dict(type=str),
        )),
        state=dict(type='str', default='present', choices=['present', 'absent', 'pure']),
    )
    bool_values = ['notEmail', 'notUsername']

    module = AnsibleKeycloakModule(argument_spec=argument_spec,
                                   supports_check_mode=True)

    result = dict(changed=False)

    realm = module.params.get('realm', module.params.get('auth_realm'))
    policy = {k: str(v) for k, v in module.params.get('policy').items()}
    for key in bool_values:
        if not policy.get(key, True):
            del policy[key]
    state = module.params.get('state')

    # Get current password policy
    data = module.api.get("/")
    current_password_policy = dict(p[:-1].split('(', 1) for p in data.get('passwordPolicy', '').split(' and ') if p)
    for key in bool_values:
        if key in current_password_policy:
            current_password_policy[key] = True

    new_password_policy = current_password_policy.copy()

    if state == 'present':
        new_password_policy.update(policy)
    elif state == 'absent':
        for key in policy.keys():
            if key in new_password_policy:
                del new_password_policy[key]
    elif state == 'pure':
        new_password_policy = policy

    if current_password_policy == new_password_policy:
        module.exit_json(password_policy=current_password_policy, **result)

    result['changed'] = True
    if module._diff:
        result['diff'] = dict(before=current_password_policy, after=new_password_policy)

    if not module.check_mode:
        module.api.put("/", payload=dict(
            passwordPolicy=" and ".join(f"{k}({v})" for k, v in new_password_policy.items())
        ))

    module.exit_json(password_policy=new_password_policy, **result)


if __name__ == '__main__':
    main()
