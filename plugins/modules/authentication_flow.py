# Copyright: (c) 2023, Marius Rieder <marius.rieder@scs.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: authentication_flow

short_description: Manage Keycloak authentication flow via Keycloak API

version_added: "20.0.0"

description:
    - This module allows the administration of Keycloak authentication flow via the Keycloak REST API.
      It requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

options:
    state:
        description: State of the flow to ensure.
        choices: ['present', 'absent']
        default: present
        type: str
    name:
        description: Name of the flow to manage.
        required: true
        aliases: ['alias']
        type: str
    id:
        description: If of the flow to manage. To allow for renaming.
        type: str
    description:
        description: Description of the flow.
        default: ''
        type: str
    type:
        description: Type of flow in case the flow has to be created.
        choices: ['basic', 'client']
        type: str
    bind:
        description: Authentication type to bind the flow to.
        choices: ['browser', 'registration', 'directGrant', 'resetCredentials', 'clientAuthentication', 'dockerAuthentication']
        type: str
    executions:
        description: List of steps and subflows of the flow.
        type: list
        elements: dict

extends_documentation_fragment:
- scsitteam.keycloak.keycloak
author:
    - Marius Rieder (@jiuka)
'''

EXAMPLES = r'''
- name: Bind Flow to resetCredentials
  authentication_flow:
    name: my reset credential
    bind: resetCredentials

- name: Recreate Browser Flow
  authentication_flow:
    name: my browser
    description: my browser based authentication
    type: basic
    executions:
      - authenticator: auth-cookie
        requirement: ALTERNATIVE

      - authenticator: auth-spnego
        requirement: DISABLED

      - authenticator: identity-provider-redirector
        requirement: ALTERNATIVE

      - name: my browser forms
        description: Username, password, otp and other auth forms.
        requirement: ALTERNATIVE
        executions:
          - authenticator: auth-username-password-form
            requirement: REQUIRED

          - name: my browser Browser - Conditional OTP
            description: Flow to determine if the OTP is required for the authentication
            requirement: CONDITIONAL
            executions:
              - authenticator: conditional-user-configured
                requirement: REQUIRED

              - authenticator: auth-otp-form
                requirement: REQUIRED
'''

RETURN = r'''
flow:
  description: Representation of the flow
  returned: success
  type: dict
  sample:
    {
      "alias": "my browser",
      "builtIn": false,
      "description": "Test Flow New",
      "id": "887da7bf-5f47-49ce-b470-3ff8c48e292d",
      "providerId": "basic-flow",
      "topLevel": true
    }
'''

from ansible_collections.scsitteam.keycloak.plugins.module_utils.module import AnsibleKeycloakModule
from ansible.module_utils.common.arg_spec import ArgumentSpecValidator
from ansible.module_utils.six.moves.urllib.parse import quote


def executions_to_keycloak(module):

    executions_validator = ArgumentSpecValidator(
        argument_spec=dict(
            authenticator=dict(type='str'),
            requirement=dict(type='str'),
            description=dict(type='str'),
            name=dict(type='str'),
            executions=dict(type='list', elements='dict'),
            type=dict(type='str', choices=['basic', 'form']),
        ),
        required_one_of=[('authenticator', 'name')],
        mutually_exclusive=[
            ('authenticator', 'name'),
            ('authenticator', 'description'),
            ('authenticator', 'executions'),
            ('authenticator', 'type'),
        ],
        required_by=dict(
            name=('description', 'executions')
        ),
    )

    executions = module.params.get('executions')
    if executions is None:
        return executions

    for idx, execution in enumerate(executions):
        result = executions_validator.validate(execution)
        if result.error_messages:
            module.fail_json(msg=", ".join(result.error_messages))

        execution.update(dict(
            level=0,
            index=idx,
        ))

    idx = 0
    while idx < len(executions):
        execution = executions[idx]
        if 'executions' in execution:
            needs_flattening = True

            sub_executions = execution.pop('executions')
            for sidx, sub_execution in enumerate(sub_executions):
                result = executions_validator.validate(sub_execution)
                if result.error_messages:
                    module.fail_json(msg=", ".join(result.error_messages))

                sub_execution.update(dict(
                    level=execution['level'] + 1,
                    index=sidx,
                    flow_name=execution['name']
                ))
                executions.insert(idx + sidx + 1, sub_execution)
        idx += 1
    return executions


def main():
    """
    Module execution

    :return:
    """
    argument_spec = dict(
        state=dict(type='str', default='present', choices=['present', 'absent']),
        id=dict(type='str'),
        name=dict(type='str', aliases=['alias'], required=True),
        description=dict(type='str', default=''),
        type=dict(type='str', choices=['basic', 'client']),
        executions=dict(type='list', elements='dict'),
        bind=dict(type='str', choices=['browser', 'registration', 'directGrant', 'resetCredentials', 'clientAuthentication', 'dockerAuthentication'])
    )

    module = AnsibleKeycloakModule(argument_spec=argument_spec,
                                   supports_check_mode=True)

    result = dict(changed=False, diff=dict(before=dict(), after=dict()))

    executions = executions_to_keycloak(module)

    keycloak_realm = module.params.get('keycloak_realm')
    state = module.params.get('state')
    id = module.params.get('id')
    name = module.params.get('name')
    description = module.params.get('description')
    type = module.params.get('type')
    bind = module.params.get('bind')

    # Get current flow
    data = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/flows")
    if id:
        current_flow = next(filter(lambda f: f['id'] == id, data), None)
        if current_flow is None:
            module.fail_json(msg=f"flow not found by id: {id}")
    else:
        current_flow = next(filter(lambda f: f['alias'] == name, data), None)

    # Build new otp policy
    if current_flow is not None:
        del current_flow['authenticationExecutions']
        new_flow = current_flow.copy()

    # Create flow if missing
    if state == 'present' and current_flow is None:
        if type is None:
            module.fail_json(msg="missing argument 'type' required to create a new flow.")
        new_flow = dict(
            alias=name,
            builtIn=False,
            description=description,
            providerId=f"{type}-flow",
            topLevel=True,
        )
        if not module.check_mode:
            module.api.post(f"/admin/realms/{ keycloak_realm }/authentication/flows", payload=new_flow)

            data = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/flows")
            new_flow = next(filter(lambda f: f['alias'] == name, data), None)
            del new_flow['authenticationExecutions']

    # Update flow
    if state == 'present':
        if id is not None and name is not None:
            new_flow['alias'] = name
        if description:
            new_flow['description'] = description

    # Remove flow
    if state == 'absent':
        if current_flow is not None:
            result['changed'] = True
            if module._diff:
                result['diff']['before']['flow'] = current_flow
                result['diff']['after']['flow'] = None

            if not module.check_mode:
                module.api.delete(f"/admin/realms/{ keycloak_realm }/authentication/flows/{current_flow['id']}")
        module.exit_json(**result)

    if current_flow != new_flow:
        result['changed'] = True
        if module._diff:
            result['diff']['before']['flow'] = current_flow
            result['diff']['after']['flow'] = new_flow

        if not module.check_mode:
            module.api.put(f"/admin/realms/{ keycloak_realm }/authentication/flows/{new_flow['id']}", payload=new_flow)

    if bind is not None:
        # Get current password policy
        data = module.api.get(f"/admin/realms/{ keycloak_realm }")
        current_bind = next((k[:-4] for k, v in data.items() if v == name), None)
        if current_bind != bind:
            if current_bind is not None:
                module.fail_json(msg=f"Flow '{name}' is already bound as {current_bind}")

            if not module.check_mode:
                module.api.put(f"/admin/realms/{ keycloak_realm }/", payload={f"{bind}Flow": name})

            result['changed'] = True
            if module._diff:
                result['diff']['before']['bind'] = current_bind
                result['diff']['after']['bind'] = bind

    # Update executions
    if state == 'present' and executions is not None:
        current_executions = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/flows/{ name }/executions")

        new_executions = current_executions.copy()

        idx = 0
        while idx < len(executions):
            if len(new_executions) > idx:
                current_execution = new_executions[idx]
            else:
                current_execution = {}
            execution = executions[idx]

            # Remove Additional from deeper levels
            if current_execution and current_execution['level'] > execution['level']:
                result['changed'] = True
                if not module.check_mode:
                    module.api.delete(f"/admin/realms/{ keycloak_realm }/authentication/executions/{new_executions[idx]['id']}")
                    new_executions = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/flows/{ quote(name) }/executions")
                else:
                    del new_executions[idx]
                continue

            if 'authenticator' in execution and (
                (not current_execution.get('providerId', None) == execution.get('authenticator'))
                or current_execution['level'] != execution['level']
            ):
                # Create new Step
                result['changed'] = True
                if not module.check_mode:
                    payload = dict(provider=execution.get('authenticator'))
                    flow_name_url = quote(execution.get('flow_name', name))
                    module.api.post(f"/admin/realms/{ keycloak_realm }/authentication/flows/{ flow_name_url }/executions/execution", payload=payload)

                    new_executions = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/flows/{ flow_name_url }/executions")
                    current_execution = new_executions[-1]
                else:
                    new_executions.insert(idx, execution)
                    current_execution = execution

            if 'name' in execution and (
                (not current_execution.get('displayName', None) == execution.get('name'))
                or current_execution['level'] != execution['level']
                or ('providerId' in current_execution) != (execution.get('type', 'basic') == 'form')
            ):
                # Create new Subflow
                result['changed'] = True
                if not module.check_mode:
                    payload = dict(
                        alias=execution.get('name'),
                        description=execution.get('description', ''),
                        provider="registration-page-form",
                        type=f"{execution.get('type', 'basic')}-flow",
                    )
                    flow_name_url = quote(execution.get('flow_name', name))
                    module.api.post(f"/admin/realms/{ keycloak_realm }/authentication/flows/{ flow_name_url  }/executions/flow", payload=payload)

                    new_executions = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/flows/{ flow_name_url }/executions")
                    current_execution = new_executions[-1]
                else:
                    new_executions.insert(idx, execution)
                    current_execution = execution

            if not module.check_mode and current_execution['index'] > execution['index']:
                for i in range(execution['index'], current_execution['index']):
                    module.api.post(f"/admin/realms/{ keycloak_realm }/authentication/executions/{current_execution['id']}/raise-priority", payload=None)

            if current_execution.get('providerId', None) == execution.get('authenticator', None):
                new_execution = current_execution.copy()
                if execution.get('requirement', None) is not None:
                    new_execution['requirement'] = execution['requirement']
                if execution.get('name', None) is not None:
                    new_execution['displayName'] = execution['name']

                if current_execution != new_execution:
                    result['changed'] = True
                    if not module.check_mode:
                        module.api.put(f"/admin/realms/{ keycloak_realm }/authentication/flows/{ name }/executions", payload=new_execution)
                    else:
                        new_executions[idx] = new_execution
            if not module.check_mode:
                new_executions = module.api.get(f"/admin/realms/{ keycloak_realm }/authentication/flows/{ name }/executions")

            idx += 1

        # Remove Additional steps
        while len(new_executions) > len(executions):
            result['changed'] = True
            if not module.check_mode:
                module.api.delete(f"/admin/realms/{ keycloak_realm }/authentication/executions/{new_executions[-1]['id']}")
            del new_executions[-1]

        if current_executions != new_executions:
            if module._diff:
                result['diff']['before']['executions'] = current_executions
                result['diff']['after']['executions'] = new_executions
        result['executions'] = new_executions

    module.exit_json(flow=new_flow, **result)


if __name__ == '__main__':
    main()
