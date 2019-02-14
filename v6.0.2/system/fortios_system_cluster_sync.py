#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2019 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# the lib use python logging can get it if the following is set in your
# Ansible config.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_system_cluster_sync
short_description: Configure FortiGate Session Life Support Protocol (FGSP) session synchronization in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS by allowing the
      user to set and modify system feature and cluster_sync category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.2
version_added: "2.8"
author:
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Requires fortiosapi library developed by Fortinet
    - Run as a local_action in your playbook
requirements:
    - fortiosapi>=0.9.8
options:
    host:
       description:
            - FortiOS or FortiGate ip address.
       required: true
    username:
        description:
            - FortiOS or FortiGate username.
        required: true
    password:
        description:
            - FortiOS or FortiGate password.
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS
              protocol
        type: bool
        default: true
    system_cluster_sync:
        description:
            - Configure FortiGate Session Life Support Protocol (FGSP) session synchronization.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            down-intfs-before-sess-sync:
                description:
                    - List of interfaces to be turned down before session synchronization is complete.
                suboptions:
                    name:
                        description:
                            - Interface name. Source system.interface.name.
                        required: true
            hb-interval:
                description:
                    - Heartbeat interval (1 - 10 sec).
            hb-lost-threshold:
                description:
                    - Lost heartbeat threshold (1 - 10).
            peerip:
                description:
                    - IP address of the interface on the peer unit that is used for the session synchronization link.
            peervd:
                description:
                    - VDOM that contains the session synchronization link interface on the peer unit. Usually both peers would have the same peervd. Source
                       system.vdom.name.
            session-sync-filter:
                description:
                    - Add one or more filters if you only want to synchronize some sessions. Use the filter to configure the types of sessions to synchronize.
                suboptions:
                    custom-service:
                        description:
                            - Only sessions using these custom services are synchronized. Use source and destination port ranges to define these custome
                               services.
                        suboptions:
                            dst-port-range:
                                description:
                                    - Custom service destination port range.
                            id:
                                description:
                                    - Custom service ID.
                                required: true
                            src-port-range:
                                description:
                                    - Custom service source port range.
                    dstaddr:
                        description:
                            - Only sessions to this IPv4 address are synchronized. You can only enter one address. To synchronize sessions for multiple
                               destination addresses, add multiple filters.
                    dstaddr6:
                        description:
                            - Only sessions to this IPv6 address are synchronized. You can only enter one address. To synchronize sessions for multiple
                               destination addresses, add multiple filters.
                    dstintf:
                        description:
                            - Only sessions to this interface are synchronized. You can only enter one interface name. To synchronize sessions to multiple
                               destination interfaces, add multiple filters. Source system.interface.name.
                    srcaddr:
                        description:
                            - Only sessions from this IPv4 address are synchronized. You can only enter one address. To synchronize sessions from multiple
                               source addresses, add multiple filters.
                    srcaddr6:
                        description:
                            - Only sessions from this IPv6 address are synchronized. You can only enter one address. To synchronize sessions from multiple
                               source addresses, add multiple filters.
                    srcintf:
                        description:
                            - Only sessions from this interface are synchronized. You can only enter one interface name. To synchronize sessions for multiple
                               source interfaces, add multiple filters. Source system.interface.name.
            slave-add-ike-routes:
                description:
                    - Enable/disable IKE route announcement on the backup unit.
                choices:
                    - enable
                    - disable
            sync-id:
                description:
                    - Sync ID.
                required: true
            syncvd:
                description:
                    - Sessions from these VDOMs are synchronized using this session synchronization configuration.
                suboptions:
                    name:
                        description:
                            - VDOM name. Source system.vdom.name.
                        required: true
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure FortiGate Session Life Support Protocol (FGSP) session synchronization.
    fortios_system_cluster_sync:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      system_cluster_sync:
        state: "present"
        down-intfs-before-sess-sync:
         -
            name: "default_name_4 (source system.interface.name)"
        hb-interval: "5"
        hb-lost-threshold: "6"
        peerip: "<your_own_value>"
        peervd: "<your_own_value> (source system.vdom.name)"
        session-sync-filter:
            custom-service:
             -
                dst-port-range: "<your_own_value>"
                id:  "12"
                src-port-range: "<your_own_value>"
            dstaddr: "<your_own_value>"
            dstaddr6: "<your_own_value>"
            dstintf: "<your_own_value> (source system.interface.name)"
            srcaddr: "<your_own_value>"
            srcaddr6: "<your_own_value>"
            srcintf: "<your_own_value> (source system.interface.name)"
        slave-add-ike-routes: "enable"
        sync-id: "21"
        syncvd:
         -
            name: "default_name_23 (source system.vdom.name)"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

'''

from ansible.module_utils.basic import AnsibleModule

fos = None


def login(data):
    host = data['host']
    username = data['username']
    password = data['password']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password)


def filter_system_cluster_sync_data(json):
    option_list = ['down-intfs-before-sess-sync', 'hb-interval', 'hb-lost-threshold',
                   'peerip', 'peervd', 'session-sync-filter',
                   'slave-add-ike-routes', 'sync-id', 'syncvd']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_multilists_attributes(data):
    multilist_attrs = []

    for attr in multilist_attrs:
        try:
            path = "data['" + "']['".join(elem for elem in attr) + "']"
            current_val = eval(path)
            flattened_val = ' '.join(elem for elem in current_val)
            exec(path + '= flattened_val')
        except BaseException:
            pass

    return data


def system_cluster_sync(data, fos):
    vdom = data['vdom']
    system_cluster_sync_data = data['system_cluster_sync']
    flattened_data = flatten_multilists_attributes(system_cluster_sync_data)
    filtered_data = filter_system_cluster_sync_data(flattened_data)
    if system_cluster_sync_data['state'] == "present":
        return fos.set('system',
                       'cluster-sync',
                       data=filtered_data,
                       vdom=vdom)

    elif system_cluster_sync_data['state'] == "absent":
        return fos.delete('system',
                          'cluster-sync',
                          mkey=filtered_data['sync-id'],
                          vdom=vdom)


def fortios_system(data, fos):
    login(data)

    methodlist = ['system_cluster_sync']
    for method in methodlist:
        if data[method]:
            resp = eval(method)(data, fos)
            break

    fos.logout()
    return not resp['status'] == "success", resp['status'] == "success", resp


def main():
    fields = {
        "host": {"required": True, "type": "str"},
        "username": {"required": True, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "system_cluster_sync": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "down-intfs-before-sess-sync": {"required": False, "type": "list",
                                                "options": {
                                                    "name": {"required": True, "type": "str"}
                                                }},
                "hb-interval": {"required": False, "type": "int"},
                "hb-lost-threshold": {"required": False, "type": "int"},
                "peerip": {"required": False, "type": "str"},
                "peervd": {"required": False, "type": "str"},
                "session-sync-filter": {"required": False, "type": "dict",
                                        "options": {
                                            "custom-service": {"required": False, "type": "list",
                                                               "options": {
                                                                   "dst-port-range": {"required": False, "type": "str"},
                                                                   "id": {"required": True, "type": "int"},
                                                                   "src-port-range": {"required": False, "type": "str"}
                                                               }},
                                            "dstaddr": {"required": False, "type": "str"},
                                            "dstaddr6": {"required": False, "type": "str"},
                                            "dstintf": {"required": False, "type": "str"},
                                            "srcaddr": {"required": False, "type": "str"},
                                            "srcaddr6": {"required": False, "type": "str"},
                                            "srcintf": {"required": False, "type": "str"}
                                        }},
                "slave-add-ike-routes": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "sync-id": {"required": True, "type": "int"},
                "syncvd": {"required": False, "type": "list",
                           "options": {
                               "name": {"required": True, "type": "str"}
                           }}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)
    try:
        from fortiosapi import FortiOSAPI
    except ImportError:
        module.fail_json(msg="fortiosapi module is required")

    global fos
    fos = FortiOSAPI()

    is_error, has_changed, result = fortios_system(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
