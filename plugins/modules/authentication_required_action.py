# Copyright: (c) 2023, Marius Rieder <marius.rieder@scs.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: authentication_required_action

short_description: Manage Keycloak required actions via Keycloak API

version_added: "20.0.0"

description:
    - This module allows the administration of Keycloak required actions via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

options:
    name:
        description: Name of the required action to manage
        required: true
        type: str
    priority:
        description: Priority of the managed action
        type: int
    state:
        description:
            - State of the required action
            - On C(enabled), the required action will be enabled.
            - On C(disabled), the required action will be disabled.
        choices: ['enabled', 'disabled']
        default: 'enabled'
        type: str
    default_action:
        description:
            - Default action state of the required action
            - On C(enabled), the required action will be enabled.
            - On C(disabled), the required action will be disabled.
        choices: ['enabled', 'disabled']
        type: str

extends_documentation_fragment:
- scsitteam.keycloak.keycloak
author:
    - Marius Rieder (@jiuka)
'''

EXAMPLES = r'''
- name: Enable Terms and Conditions
  scsitteam.kaycloak.authentication_required_action:
    name: Terms and Conditions
    state: enabled

- name: Make Configure OTP a default
  scsitteam.kaycloak.authentication_required_action:
    name: Configure OTP
    state: enabled
    default_action: enabled

- name: Disable Terms and Conditions
  scsitteam.kaycloak.authentication_required_action:
    name: Verify Email
    state: disabled
'''

RETURN = r'''
password_policy:
  description: Representation of the pasword policy
  returned: success
  type: dict
  sample:
    {
      "length": "8",
      "lowerCase": "1",
      "upperCase": "1"
      "digits": "1",
      "specialChars": "1",
    }
'''

from ansible_collections.scsitteam.keycloak.plugins.module_utils.module import AnsibleKeycloakModule

def main():
    """
    Module execution

    :return:
    """
    argument_spec = dict(
        name=dict(type='str', required=True),
        priority=dict(type='int'),
        state=dict(type='str', default='enabled', choices=['enabled', 'disabled']),
        default_action=dict(type='str', choices=['enabled', 'disabled']),
    )

    module = AnsibleKeycloakModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    result = dict(changed=False)

    keycloak_realm = module.params.get('keycloak_realm')

    name = module.params.get('name')
    priority = module.params.get('priority')
    state = module.params.get('state')
    default_action = module.params.get('default_action')

    # Get current state
    required_actions = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/required-actions")
    current_required_action = next(filter(lambda a: a['name']== name, required_actions), None)

    # Register if unregisterd
    if not current_required_action:
        unreg_required_actions = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/unregistered-required-actions")
        current_required_action = next(filter(lambda a: a['name']== name, unreg_required_actions), None)

        if current_required_action and not module.check_mode:
            module.api.post(f"/admin/realms/{ keycloak_realm }/authentication/register-required-action", payload=current_required_action)
    
            required_actions = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/required-actions")
            current_required_action = next(filter(lambda a: a['name']== name, required_actions), None)

    if not current_required_action:
        module.fail_json(f"requied action with name '{name}' not found")

    new_required_action = current_required_action.copy()

    new_required_action['enabled'] = state == 'enabled'
    if default_action is not None:
        new_required_action['defaultAction'] = default_action == 'enabled'

    if priority is not None:
        new_required_action['priority'] = priority

    if current_required_action == new_required_action:
        module.exit_json(required_action=current_required_action, **result)
    
    result['changed'] = True
    if module._diff:
        result['diff'] = dict(before=current_required_action, after=new_required_action)
       
    if not module.check_mode:
        module.api.put(f"/admin/realms/{ keycloak_realm }/authentication/required-actions/{current_required_action['providerId']}", payload=new_required_action)

    module.exit_json(required_action=new_required_action, **result)

if __name__ == '__main__':
    main()