#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
# Copyright 2018 Fortinet, Inc.
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
module: fortios_vpn.ssl.web_user_group_bookmark
short_description: Configure SSL VPN user group bookmark.
description:
    - This module is able to configure a FortiGate or FortiOS by
      allowing the user to configure vpn.ssl.web feature and user_group_bookmark category.
      Examples includes all options and need to be adjusted to datasources before usage.
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
            - FortiOS or FortiGate ip adress.
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
        default: false
    vpn.ssl.web_user_group_bookmark:
        description:
            - Configure SSL VPN user group bookmark.
        default: null
        suboptions:
            state:
                description:
                    - Indicates whether to create or remove the object
                choices:
                    - present
                    - absent
            bookmarks:
                description:
                    - Bookmark table.
                suboptions:
                    additional-params:
                        description:
                            - Additional parameters.
                    apptype:
                        description:
                            - Application type.
                        choices:
                            - citrix
                            - ftp
                            - portforward
                            - rdp
                            - smb
                            - ssh
                            - telnet
                            - vnc
                            - web
                    description:
                        description:
                            - Description.
                    folder:
                        description:
                            - Network shared file folder parameter.
                    form-data:
                        description:
                            - Form data.
                        suboptions:
                            name:
                                description:
                                    - Name.
                                required: true
                            value:
                                description:
                                    - Value.
                    host:
                        description:
                            - Host name/IP parameter.
                    listening-port:
                        description:
                            - Listening port (0 - 65535).
                    load-balancing-info:
                        description:
                            - The load balancing information or cookie which should be provided to the connection broker.
                    logon-password:
                        description:
                            - Logon password.
                    logon-user:
                        description:
                            - Logon user.
                    name:
                        description:
                            - Bookmark name.
                        required: true
                    port:
                        description:
                            - Remote port.
                    preconnection-blob:
                        description:
                            - An arbitrary string which identifies the RDP source.
                    preconnection-id:
                        description:
                            - The numeric ID of the RDP source (0-2147483648).
                    remote-port:
                        description:
                            - Remote port (0 - 65535).
                    security:
                        description:
                            - Security mode for RDP connection.
                        choices:
                            - rdp
                            - nla
                            - tls
                            - any
                    server-layout:
                        description:
                            - Server side keyboard layout.
                        choices:
                            - de-de-qwertz
                            - en-gb-qwerty
                            - en-us-qwerty
                            - es-es-qwerty
                            - fr-fr-azerty
                            - fr-ch-qwertz
                            - it-it-qwerty
                            - ja-jp-qwerty
                            - pt-br-qwerty
                            - sv-se-qwerty
                            - tr-tr-qwerty
                            - failsafe
                    show-status-window:
                        description:
                            - Enable/disable showing of status window.
                        choices:
                            - enable
                            - disable
                    sso:
                        description:
                            - Single Sign-On.
                        choices:
                            - disable
                            - static
                            - auto
                    sso-credential:
                        description:
                            - Single sign-on credentials.
                        choices:
                            - sslvpn-login
                            - alternative
                    sso-credential-sent-once:
                        description:
                            - Single sign-on credentials are only sent once to remote server.
                        choices:
                            - enable
                            - disable
                    sso-password:
                        description:
                            - SSO password.
                    sso-username:
                        description:
                            - SSO user name.
                    url:
                        description:
                            - URL parameter.
            name:
                description:
                    - Group name. Source user.group.name.
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
  - name: Configure SSL VPN user group bookmark.
    fortios_vpn.ssl.web_user_group_bookmark:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      vpn.ssl.web_user_group_bookmark:
        state: "present"
        bookmarks:
         -
            additional-params: "<your_own_value>"
            apptype: "citrix"
            description: "<your_own_value>"
            folder: "<your_own_value>"
            form-data:
             -
                name: "default_name_9"
                value: "<your_own_value>"
            host: "<your_own_value>"
            listening-port: "12"
            load-balancing-info: "<your_own_value>"
            logon-password: "<your_own_value>"
            logon-user: "<your_own_value>"
            name: "default_name_16"
            port: "17"
            preconnection-blob: "<your_own_value>"
            preconnection-id: "19"
            remote-port: "20"
            security: "rdp"
            server-layout: "de-de-qwertz"
            show-status-window: "enable"
            sso: "disable"
            sso-credential: "sslvpn-login"
            sso-credential-sent-once: "enable"
            sso-password: "<your_own_value>"
            sso-username: "<your_own_value>"
            url: "myurl.com"
        name: "default_name_30 (source user.group.name)"
'''

RETURN = '''
build:
  description: Build number of the fortigate image
  returned: always
  type: string
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: string
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: string
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: string
  sample: "key1"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: string
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: string
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: string
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: string
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: string
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: string
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: string
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


def filter_vpn.ssl.web_user_group_bookmark_data(json):
    option_list = ['bookmarks', 'name']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def vpn.ssl.web_user_group_bookmark(data, fos):
    vdom = data['vdom']
    vpn.ssl.web_user_group_bookmark_data = data['vpn.ssl.web_user_group_bookmark']
    filtered_data = filter_vpn.ssl.web_user_group_bookmark_data(
        vpn.ssl.web_user_group_bookmark_data)
    if vpn.ssl.web_user_group_bookmark_data['state'] == "present":
        return fos.set('vpn.ssl.web',
                       'user-group-bookmark',
                       data=filtered_data,
                       vdom=vdom)

    elif vpn.ssl.web_user_group_bookmark_data['state'] == "absent":
        return fos.delete('vpn.ssl.web',
                          'user-group-bookmark',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def fortios_vpn.ssl.web(data, fos):
    login(data)

    methodlist = ['vpn.ssl.web_user_group_bookmark']
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
        "https": {"required": False, "type": "bool", "default": "False"},
        "vpn.ssl.web_user_group_bookmark": {
            "required": False, "type": "dict",
            "options": {
                "state": {"required": True, "type": "str",
                          "choices": ["present", "absent"]},
                "bookmarks": {"required": False, "type": "list",
                              "options": {
                                  "additional-params": {"required": False, "type": "str"},
                                  "apptype": {"required": False, "type": "str",
                                              "choices": ["citrix", "ftp", "portforward",
                                                          "rdp", "smb", "ssh",
                                                          "telnet", "vnc", "web"]},
                                  "description": {"required": False, "type": "str"},
                                  "folder": {"required": False, "type": "str"},
                                  "form-data": {"required": False, "type": "list",
                                                "options": {
                                                    "name": {"required": True, "type": "str"},
                                                    "value": {"required": False, "type": "str"}
                                                }},
                                  "host": {"required": False, "type": "str"},
                                  "listening-port": {"required": False, "type": "int"},
                                  "load-balancing-info": {"required": False, "type": "str"},
                                  "logon-password": {"required": False, "type": "str"},
                                  "logon-user": {"required": False, "type": "str"},
                                  "name": {"required": True, "type": "str"},
                                  "port": {"required": False, "type": "int"},
                                  "preconnection-blob": {"required": False, "type": "str"},
                                  "preconnection-id": {"required": False, "type": "int"},
                                  "remote-port": {"required": False, "type": "int"},
                                  "security": {"required": False, "type": "str",
                                               "choices": ["rdp", "nla", "tls",
                                                           "any"]},
                                  "server-layout": {"required": False, "type": "str",
                                                    "choices": ["de-de-qwertz", "en-gb-qwerty", "en-us-qwerty",
                                                                "es-es-qwerty", "fr-fr-azerty", "fr-ch-qwertz",
                                                                "it-it-qwerty", "ja-jp-qwerty", "pt-br-qwerty",
                                                                "sv-se-qwerty", "tr-tr-qwerty", "failsafe"]},
                                  "show-status-window": {"required": False, "type": "str",
                                                         "choices": ["enable", "disable"]},
                                  "sso": {"required": False, "type": "str",
                                          "choices": ["disable", "static", "auto"]},
                                  "sso-credential": {"required": False, "type": "str",
                                                     "choices": ["sslvpn-login", "alternative"]},
                                  "sso-credential-sent-once": {"required": False, "type": "str",
                                                               "choices": ["enable", "disable"]},
                                  "sso-password": {"required": False, "type": "str"},
                                  "sso-username": {"required": False, "type": "str"},
                                  "url": {"required": False, "type": "str"}
                              }},
                "name": {"required": True, "type": "str"}

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

    is_error, has_changed, result = fortios_vpn.ssl.web(module.params, fos)

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
