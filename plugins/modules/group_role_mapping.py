# Copyright: (c) 2023, Marius Rieder <marius.rieder@scs.ch>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: group_role_mapping

short_description: Manage Keycloak group role mappings via Keycloak API

version_added: "21.0.0"

description:
    - This module allows the assigning and unassigning role mappings via the Keycloak REST API. It
      requires access to the REST API via OpenID Connect; the user connecting and the client being
      used must have the requisite access rights. In a default Keycloak installation, admin-cli
      and an admin user would work, as would a separate client definition with the scope tailored
      to your needs and a user having the expected roles.

options:
    realm:
        description: Realm to operate on. Default to the auth_realm option.
        type: str
    name:
        description: Name of the group to (un)assigne roles to
        required: true
        type: str
    state:
        description:
            - State of the role mapping action
            - On C(present), the roles will be assigned.
            - On C(absent), the roles will be unassigned.
            - On C(pure), only the given roles will be assigned all other will be unassigned.
        choices: ['present', 'absent', 'pure']
        default: 'present'
        type: str
    role:
        description: Name of the role to un- assigne.
        type: str
    client:
        description: Name of the client the role belongs to. Use realm roles if not defined.
        type: str
    roles:
        description: List of roles to un- assigne.
        type: list
        elements: dict
        options:
            role:
                description: Name of the role to un- assigne.
                required: true
                type: str
            client:
                description: Name of the client the role belongs to. Use realm roles if not defined.
                type: str

extends_documentation_fragment:
- scsitteam.keycloak.keycloak
author:
    - Marius Rieder (@jiuka)
'''

EXAMPLES = r'''
- name: Assigne realm-admin
  scsitteam.kaycloak.group_role_mapping:
    name: kc-admins
    client: realm-management
    role: realm-admin

- name: Unassigne realm-admin
  scsitteam.kaycloak.group_role_mapping:
    name: kc-admins
    client: realm-management
    role: realm-admin
    state: absent

- name: Assigne only realm-admin
  scsitteam.kaycloak.group_role_mapping:
    name: kc-admins
    roles:
      client: realm-management
      role: realm-admin
    state: pure
'''

RETURN = r'''
group:
  description: Representation of the group operated on
  returned: success
  type: dict
  sample:
    {
      "id": "12345678-abcd-1234-abcd-123456789abc",
      "name": "kc-admin",
      "path": "/kc-admin",
      "subGroups": []
    }
'''

from ansible_collections.scsitteam.keycloak.plugins.module_utils.module import AnsibleKeycloakModule


def main():
    """
    Module execution

    :return:
    """
    argument_spec = dict(
        realm=dict(type='str'),
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent', 'pure']),
        role=dict(type='str'),
        client=dict(type='str'),
        roles=dict(type='list', elements='dict', options=dict(
            role=dict(type='str', required=True),
            client=dict(type='str'),
        )),
    )

    module = AnsibleKeycloakModule(argument_spec=argument_spec,
                                   supports_check_mode=True,
                                   mutually_exclusive=[('role', 'roles'), ('client', 'roles')],
                                   required_one_of=[('role', 'roles')])

    result = dict(changed=False)

    realm = module.params.get('realm', module.params.get('auth_realm'))

    name = module.params.get('name')
    state = module.params.get('state')

    if module.params.get('roles'):
        roles = module.params.get('roles')
    else:
        role = dict(role=module.params.get('role'))
        if module.params.get('client'):
            role['client'] = module.params.get('client')
        roles = [role]

    # Get group
    groups = module.api.get(f"/admin/realms/{ realm }/groups?search={ name }&exact=true")
    if len(groups) != 1:
        module.fail_json(f"Group '{name}' not found", groups=groups)
    group = groups[0]
    result['group'] = group

    # Get current mappings
    current_mappings = module.api.get(f"/admin/realms/{ realm }/groups/{ group['id']}/role-mappings")
    from copy import deepcopy
    new_mappings = deepcopy(current_mappings)

    if state == 'present' or state == 'pure':
        for role in roles:
            if 'client' in role:
                if 'clientMappings' not in new_mappings:
                    new_mappings['clientMappings'] = dict()
                if role['client'] not in new_mappings['clientMappings']:
                    clients = module.api.get(f"/admin/realms/{ realm }/clients")
                    client = next(filter(lambda c: c['clientId'] ==  role['client'], clients), None)
                    if client is None:
                        module.fail_json(f"Client '{ role['client'] }' not found")
                    new_mappings['clientMappings'][role['client']] = dict(
                        id = client['id'],
                        name = client['clientId'],
                        mappings = [],
                    )

                if role['role'] not in  map(lambda m: m['name'], new_mappings['clientMappings'][role['client']]['mappings']):
                    croles = module.api.get(f"/admin/realms/{ realm }/clients/{ client['id'] }/roles?search={ role['role'] }")
                    crole = next(filter(lambda r: r['name'] ==  role['role'], croles), None)
                    if crole is None:
                        module.fail_json(f"Role '{ role['role'] }' in client '{ role['client'] }' not found")
                    new_mappings['clientMappings'][role['client']]['mappings'].append(crole)

                    if not module.check_mode:
                        module.api.post(f"/admin/realms/{ realm }/groups/{ group['id'] }/role-mappings/clients/{ client['id'] }",
                        payload=[dict(id=crole['id'], name=crole['name'], description=crole['description'])])
            else:
                if 'realmMappings' not in new_mappings:
                    new_mappings['realmMappings'] = list()

                if role['role'] not in map(lambda m: m['name'], new_mappings['realmMappings']):
                    rroles = module.api.get(f"/admin/realms/{ realm }/groups/{ group['id'] }/role-mappings/realm/available")
                    rrole = next(filter(lambda r: r['name'] ==  role['role'], rroles), None)
                    if rrole is None:
                        module.fail_json(f"Role '{ role['role'] }' in realm '{ realm }' not found")
                    new_mappings['realmMappings'].append(rrole)

                    if not module.check_mode:
                        module.api.post(f"/admin/realms/{ realm }/groups/{ group['id'] }/role-mappings/realm", payload=[rrole])

    if state == 'absent':
        for role in roles:
            if 'client' in role:
                if 'clientMappings' not in new_mappings:
                    continue

                if role['client'] not in new_mappings['clientMappings']:
                    continue

                if role['role'] in map(lambda m: m['name'], new_mappings['clientMappings'][role['client']]['mappings']):
                    crole = next(filter(lambda r: r['name'] ==  role['role'], new_mappings['clientMappings'][role['client']]['mappings']), None)
                    new_mappings['clientMappings'][role['client']]['mappings'].remove(crole)

                    if not module.check_mode:
                        module.api.delete(f"/admin/realms/{ realm }/groups/{ group['id'] }/role-mappings/clients/{ client['id'] }",
                        payload=[dict(id=crole['id'], name=crole['name'])])
            else:
                if 'realmMappings' not in new_mappings:
                    continue

                if role['role'] in map(lambda m: m['name'], new_mappings['realmMappings']):
                    rrole = next(filter(lambda r: r['name'] ==  role['role'], new_mappings['realmMappings']), None)
                    new_mappings['realmMappings'].remove(rrole)

                    if not module.check_mode:
                        module.api.delete(f"/admin/realms/{ realm }/groups/{ group['id'] }/role-mappings/realm",
                        payload=[dict(id=rrole['id'], name=rrole['name'])])

    if state == 'pure':
        for client in current_mappings.get('clientMappings', {}):
            for crole in current_mappings['clientMappings'][client]['mappings']:
                if crole['name'] not in [r['role'] for r in roles if r.get('client', None) == client]:
                    new_mappings['clientMappings'][client]['mappings'].remove(crole)

                    if not module.check_mode:
                        client_id = current_mappings['clientMappings'][client]['id']
                        module.api.delete(f"/admin/realms/{ realm }/groups/{ group['id'] }/role-mappings/clients/{ client_id }",
                        payload=[dict(id=crole['id'], name=crole['name'])])

        for rrole in current_mappings.get('realmMappings', []):
            if rrole['name'] not in [r['role'] for r in roles if not 'client' in r]:

                if rrole['name'] not in map(lambda r: r['role'], roles):
                    new_mappings['realmMappings'].remove(rrole)

                    if not module.check_mode:
                        module.api.delete(f"/admin/realms/{ realm }/groups/{ group['id'] }/role-mappings/realm",
                        payload=[dict(id=rrole['id'], name=rrole['name'])])


    if current_mappings != new_mappings:
        result['changed'] = True
    if module._diff:
        result['diff'] = dict(before=current_mappings, after=new_mappings)
    
    module.exit_json(current_mappings=current_mappings, **result)


if __name__ == '__main__':
    main()
