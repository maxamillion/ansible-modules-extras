#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2013, Adam Miller (maxamillion@fedoraproject.org)
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: firewalld
short_description: Manage arbitrary ports/services with firewalld
description:
  - This module allows for addition or deletion of services and ports either tcp or udp in either running or permanent firewalld rules.
version_added: "1.4"
options:
  service:
    description:
      - "Name of a service to add/remove to/from firewalld - service must be listed in output of firewall-cmd --get-services."
    required: false
    default: null
  port:
    description:
      - "Name of a port or port range to add/remove to/from firewalld. Must be in the form PORT/PROTOCOL or PORT-PORT/PROTOCOL for port ranges."
    required: false
    default: null
  rich_rule:
    description:
      - "Rich rule to add/remove to/from firewalld."
    required: false
    default: null
  source:
    description:
      - 'The source/network you would like to add/remove to/from firewalld'
    required: false
    default: null
    version_added: "2.0"
  interface:
    description:
      - 'The interface you would like to add/remove to/from a zone in firewalld'
    required: false
    default: null
    version_added: "2.1"
  zone:
    description:
      - 'The firewalld zone to add/remove to/from (NOTE: default zone can be configured per system but "public" is default from upstream. Available choices can be extended based on per-system configs, listed here are "out of the box" defaults).'
    required: false
    default: system-default(public)
    choices: [ "work", "drop", "internal", "external", "trusted", "home", "dmz", "public", "block" ]
  permanent:
    description:
      - "Should this configuration be in the running firewalld configuration or persist across reboots. As of Ansible version 2.3, permanent operations can operate on firewalld configs when it's not running (requires firewalld >= 3.0.9)"
    required: false
    default: null
  immediate:
    description:
      - "Should this configuration be applied immediately, if set as permanent"
    required: false
    default: false
    version_added: "1.9"
  state:
    description:
      - "Should this port accept(enabled) or reject(disabled) connections."
    required: true
    choices: [ "enabled", "disabled" ]
  timeout:
    description:
      - "The amount of time the rule should be in effect for when non-permanent."
    required: false
    default: 0
  masquerade:
    description:
      - 'The masquerade setting you would like to enable/disable to/from zones within firewalld'
    required: false
    default: null
    version_added: "2.1"
notes:
  - Not tested on any Debian based system.
  - Requires the python2 bindings of firewalld, which may not be installed by default if the distribution switched to python 3
requirements: [ 'firewalld >= 0.2.11' ]
author: "Adam Miller (@maxamillion)"
'''

EXAMPLES = '''
- firewalld: service=https permanent=true state=enabled
- firewalld: port=8081/tcp permanent=true state=disabled
- firewalld: port=161-162/udp permanent=true state=enabled
- firewalld: zone=dmz service=http permanent=true state=enabled
- firewalld: rich_rule='rule service name="ftp" audit limit value="1/m" accept' permanent=true state=enabled
- firewalld: source='192.0.2.0/24' zone=internal state=enabled
- firewalld: zone=trusted interface=eth2 permanent=true state=enabled
- firewalld: masquerade=yes state=enabled permanent=true zone=dmz
'''

from ansible.module_utils.basic import AnsibleModule

import sys

#####################
# Globals
#
fw = None
msgs = None
module = None
changed = False
immediate = None
permanent = None
Rich_Rule = None
fw_offline = False
desired_state = None
FirewallClientZoneSettings = None

module = None


#####################
# action logic
#
def action_runner(
    action,
    get_enabled_immediate, get_enabled_immediate_args,
    get_enabled_permanent, get_enabled_permanent_args,
    set_enabled_immediate, set_enabled_immediate_args,
    set_enabled_permanent, set_enabled_permanent_args,
    set_disabled_immediate, set_disabled_immediate_args,
    set_disabled_permanent, set_disabled_permanent_args
    ):
    """
    action_runner

    This fuction contains the "transaction logic" where as all operations
    follow a similar pattern in order to perform their action but simply
    call different functions to carry that action out.

    :param action: str, string of the type of firewalld module action this is (example: service, port, etc)
    :param get_enabled_immediate: func, getter function for immediate actions
    :param get_enabled_immediate_args: tuple, args for get_enabled_immediate function
    :param get_enabled_permanent: func, getter function for permanent actions
    :param get_enabled_permanent_args: tuple, args for get_enabled_permanent function
    :param set_enabled_immediate: func, setter function for immediate actions
    :param set_enabled_immediate_args: tuple, args for set_enabled_immediate function
    :param set_enabled_permanent: func, getter function for permanent actions
    :param set_enabled_permanent_args: tuple, args for get_enabled_permanent function
    :param set_disabled_immediate: func, setter function for immediate actions
    :param set_disabled_immediate_args: tuple, args for set_enabled_immediate function
    :param set_disabled_permanent: func, getter function for permanent actions
    :param set_disabled_permanent_args: tuple, args for get_enabled_permanent function

    """
    global msgs
    global immediate
    global permanent
    global changed
    global desired_state
    global permanent
    global immediate

    ## These are actions that modify msgs during the transaction for more
    ## verbose output to the user.
    custom_msg_actions = [
        'interface',
        'masquerade',
        'source',
    ]
    if action == 'interface':
        msgs_tuple = tuple(reversed(set_enabled_permanent_args))
        enabled_msg = "Changed %s to zone %s" % msgs_tuple
        disable_msg = "Removed %s from zone %s" % msgs_tuple
    elif action == 'masquerade':
        msgs_tuple = set_enabled_immediate_args
        enabled_msg = "Added masquerade to zone %s" % msgs_tuple
        disable_msg = "Removed masquerade from zone %s" % msgs_tuple
    elif action == 'source':
        msgs_tuple = tuple(reversed(set_enabled_permanent_args))
        enabled_msg = "Added %s to zone %s" % msgs_tuple
        disable_msg = "Removed %s from zone %s" % msgs_tuple

    if immediate and permanent:
        is_enabled_permanent = action_handler(
            get_enabled_permanent,
            get_enabled_permanent_args
        )
        is_enabled_immediate = action_handler(
            get_enabled_immediate,
            get_enabled_immediate_args
        )
        msgs.append('Permanent and Non-Permanent(immediate) operation')

        if desired_state == "enabled":
            if not is_enabled_permanent or not is_enabled_immediate:
                if module.check_mode:
                    module.exit_json(changed=True)
            if not is_enabled_permanent:
                action_handler(
                    set_enabled_permanent,
                    set_enabled_permanent_args
                )
                changed=True
            if not is_enabled_immediate:
                action_handler(
                    set_enabled_immediate,
                    set_enabled_immediate_args
                )
                changed=True
            if changed and (action in custom_msg_actions):
                msgs.append(enabled_msg)

        elif desired_state == "disabled":
            if is_enabled_permanent or is_enabled_immediate:
                if module.check_mode:
                    module.exit_json(changed=True)
            if is_enabled_permanent:
                action_handler(
                    set_disabled_permanent,
                    set_disabled_permanent_args
                )
                changed=True
            if is_enabled_immediate:
                action_handler(
                    set_disabled_immediate,
                    set_disabled_immediate_args
                )
                changed=True
            if changed and (action in custom_msg_actions):
                msgs.append(disable_msg)

    elif permanent and not immediate:
        is_enabled = action_handler(
            get_enabled_permanent,
            get_enabled_permanent_args
        )
        msgs.append('Permanent operation')

        if desired_state == "enabled":
            if not is_enabled:
                if module.check_mode:
                    module.exit_json(changed=True)

                action_handler(
                    set_enabled_permanent,
                    set_enabled_permanent_args
                )
                changed=True
            if changed and (action in custom_msg_actions):
                msgs.append(enabled_msg)

        elif desired_state == "disabled":
            if is_enabled:
                if module.check_mode:
                    module.exit_json(changed=True)

                action_handler(
                    set_disabled_permanent,
                    set_disabled_permanent_args
                )
                changed=True
            if changed and (action in custom_msg_actions):
                msgs.append(disable_msg)

    elif immediate and not permanent:
        is_enabled = action_handler(
            get_enabled_immediate,
            get_enabled_immediate_args
        )
        msgs.append('Non-permanent operation')

        if desired_state == "enabled":
            if not is_enabled:
                if module.check_mode:
                    module.exit_json(changed=True)

                action_handler(
                    set_enabled_immediate,
                    set_enabled_immediate_args
                )
                changed=True
            if changed and (action in custom_msg_actions):
                msgs.append(enabled_msg)

        elif desired_state == "disabled":
            if is_enabled:
                if module.check_mode:
                    module.exit_json(changed=True)

                action_handler(
                    set_disabled_immediate,
                    set_disabled_immediate_args
                )
                changed=True
            if changed and (action in custom_msg_actions):
                msgs.append(disable_msg)


#####################
# exception handling
#
def action_handler(action_func, action_func_args):
    """
    Function to wrap calls to make actions on firewalld in try/except
    logic and emit (hopefully) useful error messages
    """

    global module

    ah_msgs = []

    try:
        if type(action_func_args) is tuple:
            return action_func(*action_func_args)
        else:
            return action_func(action_func_args)
    except Exception as e:

        # If there are any commonly known errors that we should provide more
        # context for to help the users diagnose what's wrong. Handle that here
        if "INVALID_SERVICE" in "%s" % e:
            ah_msgs.append("Services are defined by port/tcp relationship and named as they are in /etc/services (on most systems)")

        # If ZONE_ALREADY_SET then no change occured
        #
        if "ZONE_ALREADY_SET" in "%s" % e:
            module.exit_json(
                changed=False,
                msg="Zone setting already set, no change made: %s" % e
            )

        if len(ah_msgs) > 0:
            module.fail_json(
                msg='ERROR: Exception caught: %s. %s' % (e, ', '.join(ah_msgs))
            )
        else:
            module.fail_json(msg='ERROR: Exception caught: %s' % e)

#####################
# fw_offline helpers
#
def get_fw_zone_settings(zone):
    if fw_offline:
        fw_zone = fw.config.get_zone(zone)
        fw_settings = FirewallClientZoneSettings(
            list(fw.config.get_zone_config(fw_zone))
        )
    else:
        fw_zone = fw.config().getZoneByName(zone)
        fw_settings = fw_zone.getSettings()

    return (fw_zone, fw_settings)

def update_fw_settings(fw_zone, fw_settings):
    if fw_offline:
        fw.config.set_zone_config(fw_zone, fw_settings.settings)
    else:
        fw_zone.update(fw_settings)

#####################
# masquerade handling
#
def get_masquerade_enabled(zone):
    if fw.queryMasquerade(zone) == True:
        return True
    else:
        return False

def get_masquerade_enabled_permanent(zone):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    if fw_settings.getMasquerade() == True:
        return True
    else:
        return False

def set_masquerade_enabled(zone):
    fw.addMasquerade(zone)

def set_masquerade_disabled(zone):
    fw.removeMasquerade(zone)

def set_masquerade_permanent(zone, masquerade):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.setMasquerade(masquerade)
    update_fw_settings(fw_zone, fw_settings)

################
# port handling
#
def get_port_enabled(zone, port_proto):
    if fw_offline:
        fw_zone, fw_settings = get_fw_zone_settings(zone)
        ports_list = fw_settings.getPorts()
    else:
        ports_list = fw.getPorts(zone)

    if port_proto in ports_list:
        return True
    else:
        return False

def set_port_enabled(zone, port, protocol, timeout):
    fw.addPort(zone, port, protocol, timeout)

def set_port_disabled(zone, port, protocol):
    fw.removePort(zone, port, protocol)

def get_port_enabled_permanent(zone, port_proto):
    fw_zone, fw_settings = get_fw_zone_settings(zone)

    if tuple(port_proto) in fw_settings.getPorts():
        return True
    else:
        return False

def set_port_enabled_permanent(zone, port, protocol):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.addPort(port, protocol)
    update_fw_settings(fw_zone, fw_settings)

def set_port_disabled_permanent(zone, port, protocol):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.removePort(port, protocol)
    update_fw_settings(fw_zone, fw_settings)

####################
# source handling
#
def get_source(zone, source):
    if source in fw.getSources(zone):
        return True
    else:
        return False

def get_source_permanent(zone, source):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    if source in fw_settings.getSources():
        return True
    else:
        return False

def add_source(zone, source):
    fw.addSource(zone, source)

def add_source_permanent(zone, source):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.addSource(source)
    update_fw_settings(fw_zone, fw_settings)

def remove_source(zone, source):
    fw.removeSource(zone, source)

def remove_source_permanent(zone, source):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.removeSource(source)
    update_fw_settings(fw_zone, fw_settings)

####################
# interface handling
#
def get_interface(zone, interface):
    if fw_offline:
        fw_zone, fw_settings = get_fw_zone_settings(zone)
        interface_list = fw_settings.getInterfaces()
    else:
        interface_list = fw.getInterfaces(zone)
    if interface in fw.getInterfaces(zone):
        return True
    else:
        return False

def change_zone_of_interface(zone, interface):
    fw.changeZoneOfInterface(zone, interface)

def remove_interface(zone, interface):
    fw.removeInterface(zone, interface)

def get_interface_permanent(zone, interface):
    fw_zone, fw_settings = get_fw_zone_settings(zone)

    if interface in fw_settings.getInterfaces():
       return True
    else:
        return False

def change_zone_of_interface_permanent(zone, interface):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    if fw_offline:
        iface_zone_objs = [ ]
        for zone in fw.config.get_zones():
            old_zone_obj = fw.config.get_zone(zone)
            if interface in old_zone_obj.interfaces:
                iface_zone_objs.append(old_zone_obj)
        if len(iface_zone_objs) > 1:
            # Even it shouldn't happen, it's actually possible that
            # the same interface is in several zone XML files
            module.fail_json(
                msg = 'ERROR: interface {} is in {} zone XML file, can only be in one'.format(
                    interface,
                    len(iface_zone_objs)
                )
            )
        old_zone_obj = iface_zone_objs[0]
        if old_zone_obj.name != zone:
            old_zone_settings = FirewallClientZoneSettings(
                fw.config.get_zone_config(old_zone_obj)
            )
            old_zone_settings.removeInterface(interface)    # remove from old
            fw.config.set_zone_config(old_zone_obj, old_zone_settings.settings)

            fw_settings.addInterface(interface)             # add to new
            fw.config.set_zone_config(fw_zone, fw_settings.settings)
    else:
        old_zone_name = fw.config().getZoneOfInterface(interface)
        if old_zone_name != zone:
            if old_zone_name:
                old_zone_obj = fw.config().getZoneByName(old_zone_name)
                old_zone_settings = old_zone_obj.getSettings()
                old_zone_settings.removeInterface(interface) # remove from old
                old_zone_obj.update(old_zone_settings)
            fw_settings.addInterface(interface)              # add to new
            fw_zone.update(fw_settings)

def remove_interface_permanent(zone, interface):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.removeInterface(interface)
    update_fw_settings(fw_zone, fw_settings)

####################
# service handling
#
def get_service_enabled(zone, service):
    if service in fw.getServices(zone):
        return True
    else:
        return False

def get_service_enabled_permanent(zone, service):
    fw_zone, fw_settings = get_fw_zone_settings(zone)

    if service in fw_settings.getServices():
        return True
    else:
        return False

def set_service_enabled(zone, service, timeout):
    fw.addService(zone, service, timeout)

def set_service_disabled(zone, service):
    fw.removeService(zone, service)

def set_service_enabled_permanent(zone, service):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.addService(service)
    update_fw_settings(fw_zone, fw_settings)

def set_service_disabled_permanent(zone, service):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.removeService(service)
    update_fw_settings(fw_zone, fw_settings)

####################
# rich rule handling
#
def get_rich_rule_enabled(zone, rule):
    # Convert the rule string to standard format
    # before checking whether it is present
    rule = str(Rich_Rule(rule_str=rule))
    if rule in fw.getRichRules(zone):
        return True
    else:
        return False

def set_rich_rule_enabled(zone, rule, timeout):
    fw.addRichRule(zone, rule, timeout)

def set_rich_rule_disabled(zone, rule):
    fw.removeRichRule(zone, rule)

def get_rich_rule_enabled_permanent(zone, rule):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    # Convert the rule string to standard format
    # before checking whether it is present
    rule = str(Rich_Rule(rule_str=rule))
    if rule in fw_settings.getRichRules():
        return True
    else:
        return False

def set_rich_rule_enabled_permanent(zone, rule):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.addRichRule(rule)
    update_fw_settings(fw_zone, fw_settings)

def set_rich_rule_disabled_permanent(zone, rule):
    fw_zone, fw_settings = get_fw_zone_settings(zone)
    fw_settings.removeRichRule(rule)
    update_fw_settings(fw_zone, fw_settings)

def main():
    global module

    ## Global Vars
    ## Handle running (online) daemon vs non-running (offline) daemon
    global fw
    global fw_offline
    global Rich_Rule
    global FirewallClientZoneSettings


    ## Allow for action_runner to not need these three always passed in
    global msgs
    global immediate
    global permanent
    global changed
    global desired_state
    global permanent
    global immediate
    changed=False
    msgs = []

    ## make module global so we don't have to pass it to action_handler every
    ## function call
    global module
    module = AnsibleModule(
        argument_spec = dict(
            service=dict(required=False,default=None),
            port=dict(required=False,default=None),
            rich_rule=dict(required=False,default=None),
            zone=dict(required=False,default=None),
            immediate=dict(type='bool',default=False),
            source=dict(required=False,default=None),
            permanent=dict(type='bool',required=False,default=False),
            state=dict(choices=['enabled', 'disabled'], required=True),
            timeout=dict(type='int',required=False,default=0),
            interface=dict(required=False,default=None),
            masquerade=dict(required=False,default=None),
            offline=dict(type='bool',required=False,default=None),
        ),
        supports_check_mode=True
    )


    ## Imports
    try:
        import firewall.config
        FW_VERSION = firewall.config.VERSION

        from firewall.client import Rich_Rule
        from firewall.client import FirewallClient
        fw = None
        fw_offline = False

        try:
            fw = FirewallClient()
            fw.getDefaultZone()
        except AttributeError:
            ## Firewalld is not currently running, permanent-only operations

            ## Import other required parts of the firewalld API
            ##
            ## NOTE:
            ##  online and offline operations do not share a common firewalld API
            from firewall.core.fw_test import Firewall_test
            from firewall.client import FirewallClientZoneSettings
            fw = Firewall_test()
            fw.start()
            fw_offline = True

    except ImportError as e:
        module.fail_json(msg='firewalld and its python 2 module are required for this module, version 2.0.11 or newer required (3.0.9 or newer for offline operations) \n %s' % e)

    if fw_offline:
        ## Pre-run version checking
        if FW_VERSION < "0.3.9":
            module.fail_json(msg='unsupported version of firewalld, offline operations require >= 3.0.9')
    else:
        ## Pre-run version checking
        if FW_VERSION < "0.2.11":
            module.fail_json(msg='unsupported version of firewalld, requires >= 2.0.11')

        ## Check for firewalld running
        try:
            if fw.connected == False:
                module.fail_json(msg='firewalld service must be running, or try with offline=true')
        except AttributeError:
            module.fail_json(msg="firewalld connection can't be established,\
                    installed version (%s) likely too old. Requires firewalld >= 2.0.11" % FW_VERSION)

    ## Handle common expectations
    ## (if nothing specified, it's an immediate-only action)
    if not module.params['permanent'] and not module.params['immediate']:
        immediate = True
    else:
        immediate = module.params['immediate']

    ## Verify required params are provided
    if module.params['interface'] != None and module.params['zone'] == None:
        module.fail_json(msg='zone is a required parameter')

    if module.params['immediate'] and fw_offline:
        module.fail_json(msg='firewall is not currently running, unable to perform immediate actions without a running firewall daemon')


    service = module.params['service']
    rich_rule = module.params['rich_rule']
    source = module.params['source']

    if module.params['port'] != None:
        port, protocol = module.params['port'].split('/')
        if protocol == None:
            module.fail_json(msg='improper port format (missing protocol?)')
    else:
        port = None

    if module.params['zone'] != None:
        zone = module.params['zone']
    else:
        if fw_offline:
            zone = fw.get_default_zone()
        else:
            zone = fw.getDefaultZone()

    permanent = module.params['permanent']
    desired_state = module.params['state']
    timeout = module.params['timeout']
    interface = module.params['interface']
    masquerade = module.params['masquerade']

    modification_count = 0
    if service != None:
        modification_count += 1
    if port != None:
        modification_count += 1
    if rich_rule != None:
        modification_count += 1
    if interface != None:
        modification_count += 1
    if masquerade != None:
        modification_count += 1

    if modification_count > 1:
        module.fail_json(msg='can only operate on port, service, rich_rule or interface at once')

    if service != None:
        action_runner(
            "service",
            get_service_enabled, (zone, service),
            get_service_enabled_permanent, (zone, service),
            set_service_enabled, (zone, service, timeout),
            set_service_enabled_permanent, (zone, service),
            set_service_disabled, (zone, service),
            set_service_disabled_permanent, (zone, service)
        )
        if changed == True:
            msgs.append("Changed service %s to %s" % (service, desired_state))

    if source != None:
        action_runner(
            "source",
            get_source, (zone, source),
            get_source_permanent, (zone, source),
            add_source, (zone, source),
            add_source_permanent, (zone, source),
            remove_source, (zone, source),
            remove_source_permanent, (zone, source)
        )

    if port != None:
        action_runner(
            "port",
            get_port_enabled, (zone, [port, protocol]),
            get_port_enabled_permanent, (zone, [port, protocol]),
            set_port_enabled, (zone, port, protocol, timeout),
            set_port_enabled_permanent, (zone, port, protocol),
            set_port_disabled, (zone, port, protocol),
            set_port_disabled_permanent, (zone, port, protocol)
        )
        if changed == True:
            msgs.append("Changed port %s to %s" % ("%s/%s" % (port, protocol), \
                        desired_state))

    if rich_rule != None:
        action_runner(
            "rich_rule",
            get_rich_rule_enabled, (zone, rich_rule),
            get_rich_rule_enabled_permanent, (zone, rich_rule),
            set_rich_rule_enabled, (zone, rich_rule, timeout),
            set_rich_rule_enabled_permanent, (zone, rich_rule),
            set_rich_rule_disabled, (zone, rich_rule),
            set_rich_rule_disabled_permanent, (zone, rich_rule)
        )
        if changed == True:
            msgs.append("Changed rich_rule %s to %s" % (rich_rule, desired_state))

    if interface != None:
        action_runner(
            "interface",
            get_interface, (zone, interface),
            get_interface_permanent, (zone, interface),
            change_zone_of_interface, (zone, interface),
            change_zone_of_interface_permanent, (zone, interface),
            remove_interface, (zone, interface),
            remove_interface_permanent, (zone, interface)
        )

    if masquerade != None:
        action_runner(
            "masquerade",
            get_masquerade_enabled, (zone),
            get_masquerade_enabled_permanent, (zone),
            set_masquerade_enabled, (zone),
            set_masquerade_permanent, (zone, True),
            set_masquerade_disabled, (zone),
            set_masquerade_permanent, (zone, False)
        )

    if fw_offline:
        msgs.append("(offline operation: only on-disk configs affected)")
    module.exit_json(changed=changed, msg=', '.join(msgs))


if __name__ == '__main__':
    main()
