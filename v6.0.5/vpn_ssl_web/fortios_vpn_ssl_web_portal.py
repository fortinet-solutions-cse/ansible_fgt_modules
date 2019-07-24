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

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fortios_vpn_ssl_web_portal
short_description: Portal in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS device by allowing the
      user to set and modify vpn_ssl_web feature and portal category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.5
version_added: "2.9"
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
            - FortiOS or FortiGate IP address.
        type: str
        required: true
    username:
        description:
            - FortiOS or FortiGate username.
        type: str
        required: true
    password:
        description:
            - FortiOS or FortiGate password.
        type: str
        default: ""
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    https:
        description:
            - Indicates if the requests towards FortiGate must use HTTPS protocol.
        type: bool
        default: true
    ssl_verify:
        description:
            - Ensures FortiGate certificate must be verified by a proper CA.
        type: bool
        default: true
    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        choices:
            - present
            - absent
    vpn_ssl_web_portal:
        description:
            - Portal.
        default: null
        type: dict
        suboptions:
            allow_user_access:
                description:
                    - Allow user access to SSL_VPN applications.
                choices:
                    - web
                    - ftp
                    - smb
                    - telnet
                    - ssh
                    - vnc
                    - rdp
                    - ping
                    - citrix
                    - portforward
            auto_connect:
                description:
                    - Enable/disable automatic connect by client when system is up.
                choices:
                    - enable
                    - disable
            bookmark_group:
                description:
                    - Portal bookmark group.
                suboptions:
                    bookmarks:
                        description:
                            - Bookmark table.
                        suboptions:
                            additional_params:
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
                            form_data:
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
                            listening_port:
                                description:
                                    - Listening port (0 _ 65535).
                            load_balancing_info:
                                description:
                                    - The load balancing information or cookie which should be provided to the connection broker.
                            logon_password:
                                description:
                                    - Logon password.
                            logon_user:
                                description:
                                    - Logon user.
                            name:
                                description:
                                    - Bookmark name.
                                required: true
                            port:
                                description:
                                    - Remote port.
                            preconnection_blob:
                                description:
                                    - An arbitrary string which identifies the RDP source.
                            preconnection_id:
                                description:
                                    - The numeric ID of the RDP source (0_2147483648).
                            remote_port:
                                description:
                                    - Remote port (0 _ 65535).
                            security:
                                description:
                                    - Security mode for RDP connection.
                                choices:
                                    - rdp
                                    - nla
                                    - tls
                                    - any
                            server_layout:
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
                            show_status_window:
                                description:
                                    - Enable/disable showing of status window.
                                choices:
                                    - enable
                                    - disable
                            sso:
                                description:
                                    - Single Sign_On.
                                choices:
                                    - disable
                                    - static
                                    - auto
                            sso_credential:
                                description:
                                    - Single sign_on credentials.
                                choices:
                                    - sslvpn-login
                                    - alternative
                            sso_credential_sent_once:
                                description:
                                    - Single sign_on credentials are only sent once to remote server.
                                choices:
                                    - enable
                                    - disable
                            sso_password:
                                description:
                                    - SSO password.
                            sso_username:
                                description:
                                    - SSO user name.
                            url:
                                description:
                                    - URL parameter.
                    name:
                        description:
                            - Bookmark group name.
                        required: true
            custom_lang:
                description:
                    - Change the web portal display language. Overrides config system global set language. You can use config system custom_language and
                       execute system custom_language to add custom language files. Source system.custom-language.name.
            customize_forticlient_download_url:
                description:
                    - Enable support of customized download URL for FortiClient.
                choices:
                    - enable
                    - disable
            display_bookmark:
                description:
                    - Enable to display the web portal bookmark widget.
                choices:
                    - enable
                    - disable
            display_connection_tools:
                description:
                    - Enable to display the web portal connection tools widget.
                choices:
                    - enable
                    - disable
            display_history:
                description:
                    - Enable to display the web portal user login history widget.
                choices:
                    - enable
                    - disable
            display_status:
                description:
                    - Enable to display the web portal status widget.
                choices:
                    - enable
                    - disable
            dns_server1:
                description:
                    - IPv4 DNS server 1.
            dns_server2:
                description:
                    - IPv4 DNS server 2.
            dns_suffix:
                description:
                    - DNS suffix.
            exclusive_routing:
                description:
                    - Enable/disable all traffic go through tunnel only.
                choices:
                    - enable
                    - disable
            forticlient_download:
                description:
                    - Enable/disable download option for FortiClient.
                choices:
                    - enable
                    - disable
            forticlient_download_method:
                description:
                    - FortiClient download method.
                choices:
                    - direct
                    - ssl-vpn
            heading:
                description:
                    - Web portal heading message.
            hide_sso_credential:
                description:
                    - Enable to prevent SSO credential being sent to client.
                choices:
                    - enable
                    - disable
            host_check:
                description:
                    - Type of host checking performed on endpoints.
                choices:
                    - none
                    - av
                    - fw
                    - av-fw
                    - custom
            host_check_interval:
                description:
                    - Periodic host check interval. Value of 0 means disabled and host checking only happens when the endpoint connects.
            host_check_policy:
                description:
                    - One or more policies to require the endpoint to have specific security software.
                suboptions:
                    name:
                        description:
                            - Host check software list name. Source vpn.ssl.web.host-check-software.name.
                        required: true
            ip_mode:
                description:
                    - Method by which users of this SSL_VPN tunnel obtain IP addresses.
                choices:
                    - range
                    - user-group
            ip_pools:
                description:
                    - IPv4 firewall source address objects reserved for SSL_VPN tunnel mode clients.
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
            ipv6_dns_server1:
                description:
                    - IPv6 DNS server 1.
            ipv6_dns_server2:
                description:
                    - IPv6 DNS server 2.
            ipv6_exclusive_routing:
                description:
                    - Enable/disable all IPv6 traffic go through tunnel only.
                choices:
                    - enable
                    - disable
            ipv6_pools:
                description:
                    - IPv4 firewall source address objects reserved for SSL_VPN tunnel mode clients.
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
            ipv6_service_restriction:
                description:
                    - Enable/disable IPv6 tunnel service restriction.
                choices:
                    - enable
                    - disable
            ipv6_split_tunneling:
                description:
                    - Enable/disable IPv6 split tunneling.
                choices:
                    - enable
                    - disable
            ipv6_split_tunneling_routing_address:
                description:
                    - IPv6 SSL_VPN tunnel mode firewall address objects that override firewall policy destination addresses to control split_tunneling access.
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address6.name firewall.addrgrp6.name.
                        required: true
            ipv6_tunnel_mode:
                description:
                    - Enable/disable IPv6 SSL_VPN tunnel mode.
                choices:
                    - enable
                    - disable
            ipv6_wins_server1:
                description:
                    - IPv6 WINS server 1.
            ipv6_wins_server2:
                description:
                    - IPv6 WINS server 2.
            keep_alive:
                description:
                    - Enable/disable automatic reconnect for FortiClient connections.
                choices:
                    - enable
                    - disable
            limit_user_logins:
                description:
                    - Enable to limit each user to one SSL_VPN session at a time.
                choices:
                    - enable
                    - disable
            mac_addr_action:
                description:
                    - Client MAC address action.
                choices:
                    - allow
                    - deny
            mac_addr_check:
                description:
                    - Enable/disable MAC address host checking.
                choices:
                    - enable
                    - disable
            mac_addr_check_rule:
                description:
                    - Client MAC address check rule.
                suboptions:
                    mac_addr_list:
                        description:
                            - Client MAC address list.
                        suboptions:
                            addr:
                                description:
                                    - Client MAC address.
                                required: true
                    mac_addr_mask:
                        description:
                            - Client MAC address mask.
                    name:
                        description:
                            - Client MAC address check rule name.
                        required: true
            macos_forticlient_download_url:
                description:
                    - Download URL for Mac FortiClient.
            name:
                description:
                    - Portal name.
                required: true
            os_check:
                description:
                    - Enable to let the FortiGate decide action based on client OS.
                choices:
                    - enable
                    - disable
            os_check_list:
                description:
                    - SSL VPN OS checks.
                suboptions:
                    action:
                        description:
                            - OS check options.
                        choices:
                            - deny
                            - allow
                            - check-up-to-date
                    latest_patch_level:
                        description:
                            - Latest OS patch level.
                    name:
                        description:
                            - Name.
                        required: true
                    tolerance:
                        description:
                            - OS patch level tolerance.
            redir_url:
                description:
                    - Client login redirect URL.
            save_password:
                description:
                    - Enable/disable FortiClient saving the user's password.
                choices:
                    - enable
                    - disable
            service_restriction:
                description:
                    - Enable/disable tunnel service restriction.
                choices:
                    - enable
                    - disable
            skip_check_for_unsupported_browser:
                description:
                    - Enable to skip host check if browser does not support it.
                choices:
                    - enable
                    - disable
            skip_check_for_unsupported_os:
                description:
                    - Enable to skip host check if client OS does not support it.
                choices:
                    - enable
                    - disable
            smb_ntlmv1_auth:
                description:
                    - Enable support of NTLMv1 for Samba authentication.
                choices:
                    - enable
                    - disable
            smbv1:
                description:
                    - Enable/disable support of SMBv1 for Samba.
                choices:
                    - enable
                    - disable
            split_dns:
                description:
                    - Split DNS for SSL VPN.
                suboptions:
                    dns_server1:
                        description:
                            - DNS server 1.
                    dns_server2:
                        description:
                            - DNS server 2.
                    domains:
                        description:
                            - Split DNS domains used for SSL_VPN clients separated by comma(,).
                    id:
                        description:
                            - ID.
                        required: true
                    ipv6_dns_server1:
                        description:
                            - IPv6 DNS server 1.
                    ipv6_dns_server2:
                        description:
                            - IPv6 DNS server 2.
            split_tunneling:
                description:
                    - Enable/disable IPv4 split tunneling.
                choices:
                    - enable
                    - disable
            split_tunneling_routing_address:
                description:
                    - IPv4 SSL_VPN tunnel mode firewall address objects that override firewall policy destination addresses to control split_tunneling access.
                suboptions:
                    name:
                        description:
                            - Address name. Source firewall.address.name firewall.addrgrp.name.
                        required: true
            theme:
                description:
                    - Web portal color scheme.
                choices:
                    - blue
                    - green
                    - red
                    - melongene
                    - mariner
            tunnel_mode:
                description:
                    - Enable/disable IPv4 SSL_VPN tunnel mode.
                choices:
                    - enable
                    - disable
            user_bookmark:
                description:
                    - Enable to allow web portal users to create their own bookmarks.
                choices:
                    - enable
                    - disable
            user_group_bookmark:
                description:
                    - Enable to allow web portal users to create bookmarks for all users in the same user group.
                choices:
                    - enable
                    - disable
            web_mode:
                description:
                    - Enable/disable SSL VPN web mode.
                choices:
                    - enable
                    - disable
            windows_forticlient_download_url:
                description:
                    - Download URL for Windows FortiClient.
            wins_server1:
                description:
                    - IPv4 WINS server 1.
            wins_server2:
                description:
                    - IPv4 WINS server 1.
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
   ssl_verify: "False"
  tasks:
  - name: Portal.
    fortios_vpn_ssl_web_portal:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      vpn_ssl_web_portal:
        allow_user_access: "web"
        auto_connect: "enable"
        bookmark_group:
         -
            bookmarks:
             -
                additional_params: "<your_own_value>"
                apptype: "citrix"
                description: "<your_own_value>"
                folder: "<your_own_value>"
                form_data:
                 -
                    name: "default_name_12"
                    value: "<your_own_value>"
                host: "<your_own_value>"
                listening_port: "15"
                load_balancing_info: "<your_own_value>"
                logon_password: "<your_own_value>"
                logon_user: "<your_own_value>"
                name: "default_name_19"
                port: "20"
                preconnection_blob: "<your_own_value>"
                preconnection_id: "22"
                remote_port: "23"
                security: "rdp"
                server_layout: "de-de-qwertz"
                show_status_window: "enable"
                sso: "disable"
                sso_credential: "sslvpn-login"
                sso_credential_sent_once: "enable"
                sso_password: "<your_own_value>"
                sso_username: "<your_own_value>"
                url: "myurl.com"
            name: "default_name_33"
        custom_lang: "<your_own_value> (source system.custom-language.name)"
        customize_forticlient_download_url: "enable"
        display_bookmark: "enable"
        display_connection_tools: "enable"
        display_history: "enable"
        display_status: "enable"
        dns_server1: "<your_own_value>"
        dns_server2: "<your_own_value>"
        dns_suffix: "<your_own_value>"
        exclusive_routing: "enable"
        forticlient_download: "enable"
        forticlient_download_method: "direct"
        heading: "<your_own_value>"
        hide_sso_credential: "enable"
        host_check: "none"
        host_check_interval: "49"
        host_check_policy:
         -
            name: "default_name_51 (source vpn.ssl.web.host-check-software.name)"
        ip_mode: "range"
        ip_pools:
         -
            name: "default_name_54 (source firewall.address.name firewall.addrgrp.name)"
        ipv6_dns_server1: "<your_own_value>"
        ipv6_dns_server2: "<your_own_value>"
        ipv6_exclusive_routing: "enable"
        ipv6_pools:
         -
            name: "default_name_59 (source firewall.address6.name firewall.addrgrp6.name)"
        ipv6_service_restriction: "enable"
        ipv6_split_tunneling: "enable"
        ipv6_split_tunneling_routing_address:
         -
            name: "default_name_63 (source firewall.address6.name firewall.addrgrp6.name)"
        ipv6_tunnel_mode: "enable"
        ipv6_wins_server1: "<your_own_value>"
        ipv6_wins_server2: "<your_own_value>"
        keep_alive: "enable"
        limit_user_logins: "enable"
        mac_addr_action: "allow"
        mac_addr_check: "enable"
        mac_addr_check_rule:
         -
            mac_addr_list:
             -
                addr: "<your_own_value>"
            mac_addr_mask: "74"
            name: "default_name_75"
        macos_forticlient_download_url: "<your_own_value>"
        name: "default_name_77"
        os_check: "enable"
        os_check_list:
         -
            action: "deny"
            latest_patch_level: "<your_own_value>"
            name: "default_name_82"
            tolerance: "83"
        redir_url: "<your_own_value>"
        save_password: "enable"
        service_restriction: "enable"
        skip_check_for_unsupported_browser: "enable"
        skip_check_for_unsupported_os: "enable"
        smb_ntlmv1_auth: "enable"
        smbv1: "enable"
        split_dns:
         -
            dns_server1: "<your_own_value>"
            dns_server2: "<your_own_value>"
            domains: "<your_own_value>"
            id:  "95"
            ipv6_dns_server1: "<your_own_value>"
            ipv6_dns_server2: "<your_own_value>"
        split_tunneling: "enable"
        split_tunneling_routing_address:
         -
            name: "default_name_100 (source firewall.address.name firewall.addrgrp.name)"
        theme: "blue"
        tunnel_mode: "enable"
        user_bookmark: "enable"
        user_group_bookmark: "enable"
        web_mode: "enable"
        windows_forticlient_download_url: "<your_own_value>"
        wins_server1: "<your_own_value>"
        wins_server2: "<your_own_value>"
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
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortios.fortios import FortiOSHandler
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG


def login(data, fos):
    host = data['host']
    username = data['username']
    password = data['password']
    ssl_verify = data['ssl_verify']

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password, verify=ssl_verify)


def filter_vpn_ssl_web_portal_data(json):
    option_list = ['allow_user_access', 'auto_connect', 'bookmark_group',
                   'custom_lang', 'customize_forticlient_download_url', 'display_bookmark',
                   'display_connection_tools', 'display_history', 'display_status',
                   'dns_server1', 'dns_server2', 'dns_suffix',
                   'exclusive_routing', 'forticlient_download', 'forticlient_download_method',
                   'heading', 'hide_sso_credential', 'host_check',
                   'host_check_interval', 'host_check_policy', 'ip_mode',
                   'ip_pools', 'ipv6_dns_server1', 'ipv6_dns_server2',
                   'ipv6_exclusive_routing', 'ipv6_pools', 'ipv6_service_restriction',
                   'ipv6_split_tunneling', 'ipv6_split_tunneling_routing_address', 'ipv6_tunnel_mode',
                   'ipv6_wins_server1', 'ipv6_wins_server2', 'keep_alive',
                   'limit_user_logins', 'mac_addr_action', 'mac_addr_check',
                   'mac_addr_check_rule', 'macos_forticlient_download_url', 'name',
                   'os_check', 'os_check_list', 'redir_url',
                   'save_password', 'service_restriction', 'skip_check_for_unsupported_browser',
                   'skip_check_for_unsupported_os', 'smb_ntlmv1_auth', 'smbv1',
                   'split_dns', 'split_tunneling', 'split_tunneling_routing_address',
                   'theme', 'tunnel_mode', 'user_bookmark',
                   'user_group_bookmark', 'web_mode', 'windows_forticlient_download_url',
                   'wins_server1', 'wins_server2']
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for elem in data:
            elem = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace('_', '-')] = underscore_to_hyphen(v)
        data = new_data

    return data


def vpn_ssl_web_portal(data, fos):
    vdom = data['vdom']
    state = data['state']
    vpn_ssl_web_portal_data = data['vpn_ssl_web_portal']
    filtered_data = underscore_to_hyphen(filter_vpn_ssl_web_portal_data(vpn_ssl_web_portal_data))

    if state == "present":
        return fos.set('vpn.ssl.web',
                       'portal',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('vpn.ssl.web',
                          'portal',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_vpn_ssl_web(data, fos):

    if data['vpn_ssl_web_portal']:
        resp = vpn_ssl_web_portal(data, fos)

    return not is_successful_status(resp), \
        resp['status'] == "success", \
        resp


def main():
    fields = {
        "host": {"required": False, "type": "str"},
        "username": {"required": False, "type": "str"},
        "password": {"required": False, "type": "str", "no_log": True},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "https": {"required": False, "type": "bool", "default": True},
        "ssl_verify": {"required": False, "type": "bool", "default": True},
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "vpn_ssl_web_portal": {
            "required": False, "type": "dict",
            "options": {
                "allow_user_access": {"required": False, "type": "str",
                                      "choices": ["web", "ftp", "smb",
                                                  "telnet", "ssh", "vnc",
                                                  "rdp", "ping", "citrix",
                                                  "portforward"]},
                "auto_connect": {"required": False, "type": "str",
                                 "choices": ["enable", "disable"]},
                "bookmark_group": {"required": False, "type": "list",
                                   "options": {
                                       "bookmarks": {"required": False, "type": "list",
                                                     "options": {
                                                         "additional_params": {"required": False, "type": "str"},
                                                         "apptype": {"required": False, "type": "str",
                                                                     "choices": ["citrix", "ftp", "portforward",
                                                                                 "rdp", "smb", "ssh",
                                                                                 "telnet", "vnc", "web"]},
                                                         "description": {"required": False, "type": "str"},
                                                         "folder": {"required": False, "type": "str"},
                                                         "form_data": {"required": False, "type": "list",
                                                                       "options": {
                                                                           "name": {"required": True, "type": "str"},
                                                                           "value": {"required": False, "type": "str"}
                                                                       }},
                                                         "host": {"required": False, "type": "str"},
                                                         "listening_port": {"required": False, "type": "int"},
                                                         "load_balancing_info": {"required": False, "type": "str"},
                                                         "logon_password": {"required": False, "type": "str"},
                                                         "logon_user": {"required": False, "type": "str"},
                                                         "name": {"required": True, "type": "str"},
                                                         "port": {"required": False, "type": "int"},
                                                         "preconnection_blob": {"required": False, "type": "str"},
                                                         "preconnection_id": {"required": False, "type": "int"},
                                                         "remote_port": {"required": False, "type": "int"},
                                                         "security": {"required": False, "type": "str",
                                                                      "choices": ["rdp", "nla", "tls",
                                                                                  "any"]},
                                                         "server_layout": {"required": False, "type": "str",
                                                                           "choices": ["de-de-qwertz", "en-gb-qwerty", "en-us-qwerty",
                                                                                       "es-es-qwerty", "fr-fr-azerty", "fr-ch-qwertz",
                                                                                       "it-it-qwerty", "ja-jp-qwerty", "pt-br-qwerty",
                                                                                       "sv-se-qwerty", "tr-tr-qwerty", "failsafe"]},
                                                         "show_status_window": {"required": False, "type": "str",
                                                                                "choices": ["enable", "disable"]},
                                                         "sso": {"required": False, "type": "str",
                                                                 "choices": ["disable", "static", "auto"]},
                                                         "sso_credential": {"required": False, "type": "str",
                                                                            "choices": ["sslvpn-login", "alternative"]},
                                                         "sso_credential_sent_once": {"required": False, "type": "str",
                                                                                      "choices": ["enable", "disable"]},
                                                         "sso_password": {"required": False, "type": "str"},
                                                         "sso_username": {"required": False, "type": "str"},
                                                         "url": {"required": False, "type": "str"}
                                                     }},
                                       "name": {"required": True, "type": "str"}
                                   }},
                "custom_lang": {"required": False, "type": "str"},
                "customize_forticlient_download_url": {"required": False, "type": "str",
                                                       "choices": ["enable", "disable"]},
                "display_bookmark": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "display_connection_tools": {"required": False, "type": "str",
                                             "choices": ["enable", "disable"]},
                "display_history": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "display_status": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "dns_server1": {"required": False, "type": "str"},
                "dns_server2": {"required": False, "type": "str"},
                "dns_suffix": {"required": False, "type": "str"},
                "exclusive_routing": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "forticlient_download": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "forticlient_download_method": {"required": False, "type": "str",
                                                "choices": ["direct", "ssl-vpn"]},
                "heading": {"required": False, "type": "str"},
                "hide_sso_credential": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                "host_check": {"required": False, "type": "str",
                               "choices": ["none", "av", "fw",
                                           "av-fw", "custom"]},
                "host_check_interval": {"required": False, "type": "int"},
                "host_check_policy": {"required": False, "type": "list",
                                      "options": {
                                          "name": {"required": True, "type": "str"}
                                      }},
                "ip_mode": {"required": False, "type": "str",
                            "choices": ["range", "user-group"]},
                "ip_pools": {"required": False, "type": "list",
                             "options": {
                                 "name": {"required": True, "type": "str"}
                             }},
                "ipv6_dns_server1": {"required": False, "type": "str"},
                "ipv6_dns_server2": {"required": False, "type": "str"},
                "ipv6_exclusive_routing": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                "ipv6_pools": {"required": False, "type": "list",
                               "options": {
                                   "name": {"required": True, "type": "str"}
                               }},
                "ipv6_service_restriction": {"required": False, "type": "str",
                                             "choices": ["enable", "disable"]},
                "ipv6_split_tunneling": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "ipv6_split_tunneling_routing_address": {"required": False, "type": "list",
                                                         "options": {
                                                             "name": {"required": True, "type": "str"}
                                                         }},
                "ipv6_tunnel_mode": {"required": False, "type": "str",
                                     "choices": ["enable", "disable"]},
                "ipv6_wins_server1": {"required": False, "type": "str"},
                "ipv6_wins_server2": {"required": False, "type": "str"},
                "keep_alive": {"required": False, "type": "str",
                               "choices": ["enable", "disable"]},
                "limit_user_logins": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "mac_addr_action": {"required": False, "type": "str",
                                    "choices": ["allow", "deny"]},
                "mac_addr_check": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "mac_addr_check_rule": {"required": False, "type": "list",
                                        "options": {
                                            "mac_addr_list": {"required": False, "type": "list",
                                                              "options": {
                                                                  "addr": {"required": True, "type": "str"}
                                                              }},
                                            "mac_addr_mask": {"required": False, "type": "int"},
                                            "name": {"required": True, "type": "str"}
                                        }},
                "macos_forticlient_download_url": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "os_check": {"required": False, "type": "str",
                             "choices": ["enable", "disable"]},
                "os_check_list": {"required": False, "type": "list",
                                  "options": {
                                      "action": {"required": False, "type": "str",
                                                 "choices": ["deny", "allow", "check-up-to-date"]},
                                      "latest_patch_level": {"required": False, "type": "str"},
                                      "name": {"required": True, "type": "str"},
                                      "tolerance": {"required": False, "type": "int"}
                                  }},
                "redir_url": {"required": False, "type": "str"},
                "save_password": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "service_restriction": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                "skip_check_for_unsupported_browser": {"required": False, "type": "str",
                                                       "choices": ["enable", "disable"]},
                "skip_check_for_unsupported_os": {"required": False, "type": "str",
                                                  "choices": ["enable", "disable"]},
                "smb_ntlmv1_auth": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "smbv1": {"required": False, "type": "str",
                          "choices": ["enable", "disable"]},
                "split_dns": {"required": False, "type": "list",
                              "options": {
                                  "dns_server1": {"required": False, "type": "str"},
                                  "dns_server2": {"required": False, "type": "str"},
                                  "domains": {"required": False, "type": "str"},
                                  "id": {"required": True, "type": "int"},
                                  "ipv6_dns_server1": {"required": False, "type": "str"},
                                  "ipv6_dns_server2": {"required": False, "type": "str"}
                              }},
                "split_tunneling": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "split_tunneling_routing_address": {"required": False, "type": "list",
                                                    "options": {
                                                        "name": {"required": True, "type": "str"}
                                                    }},
                "theme": {"required": False, "type": "str",
                          "choices": ["blue", "green", "red",
                                      "melongene", "mariner"]},
                "tunnel_mode": {"required": False, "type": "str",
                                "choices": ["enable", "disable"]},
                "user_bookmark": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "user_group_bookmark": {"required": False, "type": "str",
                                        "choices": ["enable", "disable"]},
                "web_mode": {"required": False, "type": "str",
                             "choices": ["enable", "disable"]},
                "windows_forticlient_download_url": {"required": False, "type": "str"},
                "wins_server1": {"required": False, "type": "str"},
                "wins_server2": {"required": False, "type": "str"}

            }
        }
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=False)

    legacy_mode = 'host' in module.params and module.params['host'] is not None and \
                  'username' in module.params and module.params['username'] is not None and \
                  'password' in module.params and module.params['password'] is not None

    if not legacy_mode:
        if module._socket_path:
            connection = Connection(module._socket_path)
            fos = FortiOSHandler(connection)

            is_error, has_changed, result = fortios_vpn_ssl_web(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_vpn_ssl_web(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
