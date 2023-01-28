# Copyright: (c) 2023, Marius Rieder <marius.rieder@scs.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: authentication_otp_policy

short_description: Manage Keycloak otp policy via Keycloak API

version_added: "20.0.0"

description:
    - This module allows the administration of Keycloak otp policy via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

options:
    type:
        description: 
            - OTP Type, time or counter based OTP.
            - On C(totp) time based OTP is used.
            - On C(hotp) counter based OTP is used.
        choices: ['totp', 'hotp']
        type: str

    algorithm:
        description: Hash algorithm to use for the OTP.
        choices: ['HmacSHA1', 'HmacSHA256', 'HmacSHA512']
        type: str
        aliases: ['hash', 'algo']

    digits:
        description: Length of generated OTP.
        choices: [6, 8]
        type: int

    look_ahead:
        description: How far ahead the server looks in case the token generator and server are out of time or counter sync.
        type: int

    period:
        description: Seconds an OTP token is valid.
        type: int

    reusable:
        description: Possibility to use the same OTP code again after successful authentication.
        type: bool

    initial_counter:
        description: Counter to start C(hotp) counter at. Must be between 1 and 120.
        type: int
    

extends_documentation_fragment:
- scsitteam.keycloak.keycloak
author:
    - Marius Rieder (@jiuka)
'''

EXAMPLES = r'''
- name: Use 8 Digit Counter OTP
  scsitteam.kaycloak.authentication_otp_policy:
    type: hotp
    digits: 8

- name: Use 6 Digit Time OTP w/ SHA512
  scsitteam.kaycloak.authentication_otp_policy:
    type: totp
    digits: 6
    algorithm: HmacSHA512
'''

RETURN = r'''
required_action:
  description: Representation of the required action
  returned: success
  type: dict
  sample:
    {
      "otpPolicyAlgorithm": "HmacSHA1",
      "otpPolicyCodeReusable": false,
      "otpPolicyDigits": 6,
      "otpPolicyInitialCounter": 1,
      "otpPolicyLookAheadWindow": 1,
      "otpPolicyPeriod": 30,
      "otpPolicyType": "totp"
    }
'''

from ansible_collections.scsitteam.keycloak.plugins.module_utils.module import AnsibleKeycloakModule

def main():
    """
    Module execution

    :return:
    """
    argument_spec = dict(
        type=dict(type='str', choices=['totp', 'hotp']),
        algorithm=dict(type='str', choices=['HmacSHA1', 'HmacSHA256', 'HmacSHA512'], aliases=['algo', 'hash']),
        digits=dict(type='int', choices=[6, 8]),
        look_ahead=dict(type='int'),
        period=dict(type='int'),
        reusable=dict(type='bool'),
        initial_counter=dict(type='int'),
    )

    module = AnsibleKeycloakModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    if module.params.get('initial_counter') is not None:
        initial_counter = module.params.get('initial_counter')
        if initial_counter < 1 or initial_counter > 120:
            module.fail_json(msg=f"value of initial_counter must be between 1 and 120, got: {initial_counter}")

    result = dict(changed=False)

    keycloak_realm = module.params.get('keycloak_realm')

    # Get current otp policy
    data = module.api.get(f"/admin/realms/{ keycloak_realm }")
    current_otp_policy = {k: v for k,v in data.items() if k.startswith('otpPolicy')}

    # Build new otp policy
    new_opt_policy = current_otp_policy.copy()
    if module.params.get('algorithm'):
        new_opt_policy['otpPolicyAlgorithm'] = module.params.get('algorithm')
    if module.params.get('reusable'):
        new_opt_policy['otpPolicyCodeReusable'] = module.params.get('reusable')
    if module.params.get('digits'):
        new_opt_policy['otpPolicyDigits'] = module.params.get('digits')
    if module.params.get('initial_counter'):
        new_opt_policy['otpPolicyInitialCounter'] = module.params.get('initial_counter')
    if module.params.get('look_ahead'):
        new_opt_policy['otpPolicyLookAheadWindow'] = module.params.get('look_ahead')
    if module.params.get('period'):
        new_opt_policy['otpPolicyPeriod'] = module.params.get('period')
    if module.params.get('type'):
        new_opt_policy['otpPolicyType'] = module.params.get('type')

    if current_otp_policy == new_opt_policy:
        module.exit_json(otp_policy=current_otp_policy, **result)

    result['changed'] = True
    if module._diff:
        result['diff'] = dict(before=current_otp_policy, after=new_opt_policy)
       
    if not module.check_mode:
        module.api.put(f"/admin/realms/{ keycloak_realm }", payload=new_opt_policy)

    module.exit_json(otp_policy=new_opt_policy, **result)

if __name__ == '__main__':
    main()