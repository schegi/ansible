#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2018, Juan Manuel Parrilla <jparrill@redhat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: ipa_vault_archive
author: Juan Manuel Parrilla (@jparrill)
short_description: Upload/retrieve content to FreeIPA vaults
description:
- Archive & retrieve secret from/to vaults
options:
    cn:
        description:
        - Vault name.
        - Can not be changed as it is the unique identifier.
        required: true
        aliases: ["name"]
    description:
        description:
        - Description
    ipavaulttype:
        description:
        - Vault types are based on security level.
        default: "symmetric"
        choices: ["standard", "symmetric", "asymmetric"]
        required: true
        aliases: ["vault_type"]
    ipavaultpublickey:
        description:
        - Public key.
        aliases: ["vault_public_key"]
    ipavaultsalt:
        description:
        - Vault Salt.
        aliases: ["vault_salt"]
    username:
        description:
        - Any user can own one or more user vaults.
        - Mutually exclusive with service.
        aliases: ["user"]
    service:
        description:
        - Any service can own one or more service vaults.
        - Mutually exclusive with user.
    state:
        description:
        - State to ensure.
        default: "present"
        choices: ["present", "absent"]
    replace:
        description:
        - Force replace the existant vault on IPA server.
        type: bool
        default: False
        choices: ["True", "False"]
    validate_certs:
        description:
        - Validate IPA server certificates.
        type: bool
        default: true
extends_documentation_fragment: ipa.documentation
version_added: "2.7"
'''

EXAMPLES = '''
# Ensure vault is present
- ipa_vault:
    name: vault01
    type: standard
    user: user01
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
    validate_certs: false

# Ensure vault is present for Admin user
- ipa_vault:
    name: vault01
    vault_type: standard
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

# Ensure vault is absent
- ipa_vault:
    name: vault01
    vault_type: standard
    user: user01
    state: absent
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret

# Modify vault if already exists
- ipa_vault:
    name: vault01
    vault_type: standard
    description: "Vault for test"
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
    replace: True

# Get vault info if already exists
- ipa_vault:
    name: vault01
    ipa_host: ipa.example.com
    ipa_user: admin
    ipa_pass: topsecret
'''

RETURN = '''
vault:
  description: Vault as returned by IPA API
  returned: always
  type: dict
'''

import traceback

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ipa import IPAClient, ipa_argument_spec
from ansible.module_utils._text import to_native


class VaultIPAClient(IPAClient):
    def __init__(self, module, host, port, protocol):
        super(VaultIPAClient, self).__init__(module, host, port, protocol)

    def vault_find(self, name):
        return self._post_json(method='vault_find', name=None, item={'all': True, 'cn': name})

    def vaultconfig_show(self, name):
        return self.get_json_url()

    def vault_archive_internal(self, name, item):
        return self._post_json(method='vault_archive_internal', name=name, item=item)

    def vault_retrieve_internal(self, name, item):
        return self._post_json(method='vault_retrieve_internal', name=name, item=item)


def vault_archive_dict(vault_session_key=None, vault_data=None, vault_nonce=None, service=None):
    # Vault archive model
    vault = {}
    if vault_session_key is not None:
        vault['session_key'] = vault_session_key
    if vault_data is not None:
        vault['vault_data'] = vault_data
    if vault_nonce is not None:
        vault['nonce'] = vault_nonce
    if service is not None:
        vault['service'] = service
    return vault


def vault_retrieve_dict(vault_session_key=None, service=None):
    # Vault retrieve model
    vault = {}

    if vault_session_key is not None:
        vault['session_key'] = vault_session_key
    if service is not None:
        vault['service'] = service
    return vault


def _wrap_data(self, algo, json_vault_data):
    """Encrypt data with wrapped session key and transport cert
    :param bytes algo: wrapping algorithm instance
    :param bytes json_vault_data: dumped vault data
    :return:
    """
    nonce = os.urandom(algo.block_size // 8)

    # wrap vault_data with session key
    padder = PKCS7(algo.block_size).padder()
    padded_data = padder.update(json_vault_data)
    padded_data += padder.finalize()

    cipher = Cipher(algo, modes.CBC(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    wrapped_vault_data = encryptor.update(padded_data) + encryptor.finalize()

    return nonce, wrapped_vault_data


def generate_session_key():
    key_length = max(algorithms.TripleDES.key_sizes)
    algo = algorithms.TripleDES(os.urandom(key_length // 8))
    return algo


def crypto_reqs():
    #transport_cert = 
    pass


def ensure(module, client):
    state = module.params['state']
    name = module.params['cn']
    user = module.params['username']

    ipa_vault = client.vault_find(name=name)
    ipa_vault_conf = client.vaultconfig_show(name=name)
    module.fail_json(msg=ipa_vault_conf)
    

    vault_retrieve = vault_retrieve_dict(vault_session_key=module.params['vault_session_key'],
                                  service=module.params['service'])
    
    ipa_vault_data = client.vault_retrieve_internal(name, item=vault_retrieve)

    vault_archive = vault_archive_dict(vault_session_key=module.params['vault_session_key'],
                                  vault_data=module.params['vault_data'],
                                  vault_nonce=module.params['vault_nonce'],
                                  service=module.params['service'])

    

    changed = False
    if state == 'present':
        if ipa_vault:
            # Vault exists
            changed = True
            if not module.check_mode:
                ipa_vault = client.vault_archive_internal(name, item=vault_archive)

    else:
        ipa_vault = client.vault_retrieve_internal(name, item=vault_retrieve)

    return changed, ipa_vault


def main():
    argument_spec = ipa_argument_spec()
    argument_spec.update(cn=dict(type='str', required=True, aliases=['name']),
                         description=dict(type='str'),
                         vault_data=dict(type='str', aliases=['vault_data']),
                         vault_session_key=dict(type='str', aliases=['vault_session_key']),
                         service=dict(type='str'),
                         state=dict(type='str', default='present', choices=['present', 'absent']),
                         username=dict(type='list', aliases=['user']))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )

    client = VaultIPAClient(module=module,
                            host=module.params['ipa_host'],
                            port=module.params['ipa_port'],
                            protocol=module.params['ipa_prot'])
    try:
        client.login(username=module.params['ipa_user'],
                     password=module.params['ipa_pass'])

        module.fail_json(msg=dir(client))
        changed, vault = ensure(module, client)
        module.exit_json(changed=changed, vault=vault)
    except Exception as e:
        module.fail_json(msg=to_native(e), exception=traceback.format_exc())


if __name__ == '__main__':
    main()
