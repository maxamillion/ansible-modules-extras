#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to configure yum repositories
(c) 2015, Adam Miller <maxamillion@fedoraproject.org>

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

DOCUMENTATION = '''
---
module: yum_config_manager
short_description: Enable, Disable, or Add new yum repositories.
description:
  - This module will add a new yum repository or to enable/disable a previously
    existing yum repository.
version_added: "1.9"
options:
  state:
    description:
      - "Desired state of the repository: enabled, disabled, present"
    required: True
    default: None
  name:
    description:
      - "Name of repository needed to be created/deleted"
      - "NOTE: Required when enabling/disabling a repository"
    required: False
    default: None
  repofile:
    description:
      - "Location of the YUM repo file to use, can be a path or an url."
      - "NOTE: Required when adding a new repository"
    required: False
    default: None
author: Adam Miller <maxamillion@fedoraproject.org>
'''

EXAMPLES = '''
yum_config_manager: state=enabled name=epel-testing
yum_config_manager: state=present repofile="http://example.com/repos/myyumrepo.repo"
'''

ycm = '/usr/bin/yum-config-manager'

def main():

    module = AnsibleModule(
        argument_spec = dict(
            state=dict(
                required=True,
                default=None,
                choices=['enabled','disabled','present']
            ),
            name=dict(
                required=False,
                default=None,
            ),
            repofile=dict(
                required=False,
                default=None,
            ),
        ),
        supports_check_mode=False
    )



    if module.params['state'] in ('enabled', 'disabled'):

        if module.params['name'] == None:
            module.fail_json(msg='No repo name provided')

        cmd = '%s --%s %s' % (
            ycm,
            module.params['state'][:-1],
            module.params['name']
        )

    elif module.params['state'] == 'present':
        if module.params['repofile'] == None:
            module.fail_json(msg='No repofile provided')
        cmd = '%s --add-repo=%s' % (ycm, module.params['repofile'])
    else:
        module.fail_json(msg="Invalid State")

    rc, out, err = module.run_command(cmd)

    if rc != 0:
        module.fail_json(
            msg="rc of commmand is non-zero",
            cmd=args,
            stdout=out,
            stderr=err,
            rc=rc,
            changed=True,
        )
    else:
        # If rc was non-zero, it would have failed
        module.exit_json(
            cmd=args,
            stdout=run_result['stdout'].rstrip("\r\n"),
            stderr=run_result['stderr'].rstrip("\r\n"),
            rc=run_result['rc'],
            changed=True,
        )

#################################################
# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.splitter import *

main()

