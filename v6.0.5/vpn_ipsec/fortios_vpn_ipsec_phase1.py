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
module: fortios_vpn_ipsec_phase1
short_description: Configure VPN remote gateway in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS device by allowing the
      user to set and modify vpn_ipsec feature and phase1 category.
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
    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        choices:
            - present
            - absent
    vpn_ipsec_phase1:
        description:
            - Configure VPN remote gateway.
        default: null
        type: dict
        suboptions:
            acct_verify:
                description:
                    - Enable/disable verification of RADIUS accounting record.
                choices:
                    - enable
                    - disable
            add_gw_route:
                description:
                    - Enable/disable automatically add a route to the remote gateway.
                choices:
                    - enable
                    - disable
            add_route:
                description:
                    - Enable/disable control addition of a route to peer destination selector.
                choices:
                    - disable
                    - enable
            assign_ip:
                description:
                    - Enable/disable assignment of IP to IPsec interface via configuration method.
                choices:
                    - disable
                    - enable
            assign_ip_from:
                description:
                    - Method by which the IP address will be assigned.
                choices:
                    - range
                    - usrgrp
                    - dhcp
                    - name
            authmethod:
                description:
                    - Authentication method.
                choices:
                    - psk
                    - signature
            authmethod_remote:
                description:
                    - Authentication method (remote side).
                choices:
                    - psk
                    - signature
            authpasswd:
                description:
                    - XAuth password (max 35 characters).
            authusr:
                description:
                    - XAuth user name.
            authusrgrp:
                description:
                    - Authentication user group. Source user.group.name.
            auto_negotiate:
                description:
                    - Enable/disable automatic initiation of IKE SA negotiation.
                choices:
                    - enable
                    - disable
            backup_gateway:
                description:
                    - Instruct unity clients about the backup gateway address(es).
                suboptions:
                    address:
                        description:
                            - Address of backup gateway.
                        required: true
            banner:
                description:
                    - Message that unity client should display after connecting.
            cert_id_validation:
                description:
                    - Enable/disable cross validation of peer ID and the identity in the peer's certificate as specified in RFC 4945.
                choices:
                    - enable
                    - disable
            certificate:
                description:
                    - Names of up to 4 signed personal certificates.
                suboptions:
                    name:
                        description:
                            - Certificate name. Source vpn.certificate.local.name.
                        required: true
            childless_ike:
                description:
                    - Enable/disable childless IKEv2 initiation (RFC 6023).
                choices:
                    - enable
                    - disable
            client_auto_negotiate:
                description:
                    - Enable/disable allowing the VPN client to bring up the tunnel when there is no traffic.
                choices:
                    - disable
                    - enable
            client_keep_alive:
                description:
                    - Enable/disable allowing the VPN client to keep the tunnel up when there is no traffic.
                choices:
                    - disable
                    - enable
            comments:
                description:
                    - Comment.
            dhgrp:
                description:
                    - DH group.
                choices:
                    - 1
                    - 2
                    - 5
                    - 14
                    - 15
                    - 16
                    - 17
                    - 18
                    - 19
                    - 20
                    - 21
                    - 27
                    - 28
                    - 29
                    - 30
                    - 31
            digital_signature_auth:
                description:
                    - Enable/disable IKEv2 Digital Signature Authentication (RFC 7427).
                choices:
                    - enable
                    - disable
            distance:
                description:
                    - Distance for routes added by IKE (1 _ 255).
            dns_mode:
                description:
                    - DNS server mode.
                choices:
                    - manual
                    - auto
            domain:
                description:
                    - Instruct unity clients about the default DNS domain.
            dpd:
                description:
                    - Dead Peer Detection mode.
                choices:
                    - disable
                    - on-idle
                    - on-demand
            dpd_retrycount:
                description:
                    - Number of DPD retry attempts.
            dpd_retryinterval:
                description:
                    - DPD retry interval.
            eap:
                description:
                    - Enable/disable IKEv2 EAP authentication.
                choices:
                    - enable
                    - disable
            eap_identity:
                description:
                    - IKEv2 EAP peer identity type.
                choices:
                    - use-id-payload
                    - send-request
            enforce_unique_id:
                description:
                    - Enable/disable peer ID uniqueness check.
                choices:
                    - disable
                    - keep-new
                    - keep-old
            forticlient_enforcement:
                description:
                    - Enable/disable FortiClient enforcement.
                choices:
                    - enable
                    - disable
            fragmentation:
                description:
                    - Enable/disable fragment IKE message on re_transmission.
                choices:
                    - enable
                    - disable
            fragmentation_mtu:
                description:
                    - IKE fragmentation MTU (500 _ 16000).
            group_authentication:
                description:
                    - Enable/disable IKEv2 IDi group authentication.
                choices:
                    - enable
                    - disable
            group_authentication_secret:
                description:
                    - Password for IKEv2 IDi group authentication.  (ASCII string or hexadecimal indicated by a leading 0x.)
            ha_sync_esp_seqno:
                description:
                    - Enable/disable sequence number jump ahead for IPsec HA.
                choices:
                    - enable
                    - disable
            idle_timeout:
                description:
                    - Enable/disable IPsec tunnel idle timeout.
                choices:
                    - enable
                    - disable
            idle_timeoutinterval:
                description:
                    - IPsec tunnel idle timeout in minutes (5 _ 43200).
            ike_version:
                description:
                    - IKE protocol version.
                choices:
                    - 1
                    - 2
            include_local_lan:
                description:
                    - Enable/disable allow local LAN access on unity clients.
                choices:
                    - disable
                    - enable
            interface:
                description:
                    - Local physical, aggregate, or VLAN outgoing interface. Source system.interface.name.
            ipv4_dns_server1:
                description:
                    - IPv4 DNS server 1.
            ipv4_dns_server2:
                description:
                    - IPv4 DNS server 2.
            ipv4_dns_server3:
                description:
                    - IPv4 DNS server 3.
            ipv4_end_ip:
                description:
                    - End of IPv4 range.
            ipv4_exclude_range:
                description:
                    - Configuration Method IPv4 exclude ranges.
                suboptions:
                    end_ip:
                        description:
                            - End of IPv4 exclusive range.
                    id:
                        description:
                            - ID.
                        required: true
                    start_ip:
                        description:
                            - Start of IPv4 exclusive range.
            ipv4_name:
                description:
                    - IPv4 address name. Source firewall.address.name firewall.addrgrp.name.
            ipv4_netmask:
                description:
                    - IPv4 Netmask.
            ipv4_split_exclude:
                description:
                    - IPv4 subnets that should not be sent over the IPsec tunnel. Source firewall.address.name firewall.addrgrp.name.
            ipv4_split_include:
                description:
                    - IPv4 split_include subnets. Source firewall.address.name firewall.addrgrp.name.
            ipv4_start_ip:
                description:
                    - Start of IPv4 range.
            ipv4_wins_server1:
                description:
                    - WINS server 1.
            ipv4_wins_server2:
                description:
                    - WINS server 2.
            ipv6_dns_server1:
                description:
                    - IPv6 DNS server 1.
            ipv6_dns_server2:
                description:
                    - IPv6 DNS server 2.
            ipv6_dns_server3:
                description:
                    - IPv6 DNS server 3.
            ipv6_end_ip:
                description:
                    - End of IPv6 range.
            ipv6_exclude_range:
                description:
                    - Configuration method IPv6 exclude ranges.
                suboptions:
                    end_ip:
                        description:
                            - End of IPv6 exclusive range.
                    id:
                        description:
                            - ID.
                        required: true
                    start_ip:
                        description:
                            - Start of IPv6 exclusive range.
            ipv6_name:
                description:
                    - IPv6 address name. Source firewall.address6.name firewall.addrgrp6.name.
            ipv6_prefix:
                description:
                    - IPv6 prefix.
            ipv6_split_exclude:
                description:
                    - IPv6 subnets that should not be sent over the IPsec tunnel. Source firewall.address6.name firewall.addrgrp6.name.
            ipv6_split_include:
                description:
                    - IPv6 split_include subnets. Source firewall.address6.name firewall.addrgrp6.name.
            ipv6_start_ip:
                description:
                    - Start of IPv6 range.
            keepalive:
                description:
                    - NAT_T keep alive interval.
            keylife:
                description:
                    - Time to wait in seconds before phase 1 encryption key expires.
            local_gw:
                description:
                    - Local VPN gateway.
            localid:
                description:
                    - Local ID.
            localid_type:
                description:
                    - Local ID type.
                choices:
                    - auto
                    - fqdn
                    - user-fqdn
                    - keyid
                    - address
                    - asn1dn
            mesh_selector_type:
                description:
                    - Add selectors containing subsets of the configuration depending on traffic.
                choices:
                    - disable
                    - subnet
                    - host
            mode:
                description:
                    - ID protection mode used to establish a secure channel.
                choices:
                    - aggressive
                    - main
            mode_cfg:
                description:
                    - Enable/disable configuration method.
                choices:
                    - disable
                    - enable
            name:
                description:
                    - IPsec remote gateway name.
                required: true
            nattraversal:
                description:
                    - Enable/disable NAT traversal.
                choices:
                    - enable
                    - disable
                    - forced
            negotiate_timeout:
                description:
                    - IKE SA negotiation timeout in seconds (1 _ 300).
            peer:
                description:
                    - Accept this peer certificate. Source user.peer.name.
            peergrp:
                description:
                    - Accept this peer certificate group. Source user.peergrp.name.
            peerid:
                description:
                    - Accept this peer identity.
            peertype:
                description:
                    - Accept this peer type.
                choices:
                    - any
                    - one
                    - dialup
                    - peer
                    - peergrp
            ppk:
                description:
                    - Enable/disable IKEv2 Postquantum Preshared Key (PPK).
                choices:
                    - disable
                    - allow
                    - require
            ppk_identity:
                description:
                    - IKEv2 Postquantum Preshared Key Identity.
            ppk_secret:
                description:
                    - IKEv2 Postquantum Preshared Key (ASCII string or hexadecimal encoded with a leading 0x).
            priority:
                description:
                    - Priority for routes added by IKE (0 _ 4294967295).
            proposal:
                description:
                    - Phase1 proposal.
                choices:
                    - des-md5
                    - des-sha1
                    - des-sha256
                    - des-sha384
                    - des-sha512
            psksecret:
                description:
                    - Pre_shared secret for PSK authentication (ASCII string or hexadecimal encoded with a leading 0x).
            psksecret_remote:
                description:
                    - Pre_shared secret for remote side PSK authentication (ASCII string or hexadecimal encoded with a leading 0x).
            reauth:
                description:
                    - Enable/disable re_authentication upon IKE SA lifetime expiration.
                choices:
                    - disable
                    - enable
            rekey:
                description:
                    - Enable/disable phase1 rekey.
                choices:
                    - enable
                    - disable
            remote_gw:
                description:
                    - Remote VPN gateway.
            remotegw_ddns:
                description:
                    - Domain name of remote gateway (eg. name.DDNS.com).
            rsa_signature_format:
                description:
                    - Digital Signature Authentication RSA signature format.
                choices:
                    - pkcs1
                    - pss
            save_password:
                description:
                    - Enable/disable saving XAuth username and password on VPN clients.
                choices:
                    - disable
                    - enable
            send_cert_chain:
                description:
                    - Enable/disable sending certificate chain.
                choices:
                    - enable
                    - disable
            signature_hash_alg:
                description:
                    - Digital Signature Authentication hash algorithms.
                choices:
                    - sha1
                    - sha2-256
                    - sha2-384
                    - sha2-512
            split_include_service:
                description:
                    - Split_include services. Source firewall.service.group.name firewall.service.custom.name.
            suite_b:
                description:
                    - Use Suite_B.
                choices:
                    - disable
                    - suite-b-gcm-128
                    - suite-b-gcm-256
            type:
                description:
                    - Remote gateway type.
                choices:
                    - static
                    - dynamic
                    - ddns
            unity_support:
                description:
                    - Enable/disable support for Cisco UNITY Configuration Method extensions.
                choices:
                    - disable
                    - enable
            usrgrp:
                description:
                    - User group name for dialup peers. Source user.group.name.
            wizard_type:
                description:
                    - GUI VPN Wizard Type.
                choices:
                    - custom
                    - dialup-forticlient
                    - dialup-ios
                    - dialup-android
                    - dialup-windows
                    - dialup-cisco
                    - static-fortigate
                    - dialup-fortigate
                    - static-cisco
                    - dialup-cisco-fw
            xauthtype:
                description:
                    - XAuth type.
                choices:
                    - disable
                    - client
                    - pap
                    - chap
                    - auto
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure VPN remote gateway.
    fortios_vpn_ipsec_phase1:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      vpn_ipsec_phase1:
        acct_verify: "enable"
        add_gw_route: "enable"
        add_route: "disable"
        assign_ip: "disable"
        assign_ip_from: "range"
        authmethod: "psk"
        authmethod_remote: "psk"
        authpasswd: "<your_own_value>"
        authusr: "<your_own_value>"
        authusrgrp: "<your_own_value> (source user.group.name)"
        auto_negotiate: "enable"
        backup_gateway:
         -
            address: "<your_own_value>"
        banner: "<your_own_value>"
        cert_id_validation: "enable"
        certificate:
         -
            name: "default_name_19 (source vpn.certificate.local.name)"
        childless_ike: "enable"
        client_auto_negotiate: "disable"
        client_keep_alive: "disable"
        comments: "<your_own_value>"
        dhgrp: "1"
        digital_signature_auth: "enable"
        distance: "26"
        dns_mode: "manual"
        domain: "<your_own_value>"
        dpd: "disable"
        dpd_retrycount: "30"
        dpd_retryinterval: "<your_own_value>"
        eap: "enable"
        eap_identity: "use-id-payload"
        enforce_unique_id: "disable"
        forticlient_enforcement: "enable"
        fragmentation: "enable"
        fragmentation_mtu: "37"
        group_authentication: "enable"
        group_authentication_secret: "<your_own_value>"
        ha_sync_esp_seqno: "enable"
        idle_timeout: "enable"
        idle_timeoutinterval: "42"
        ike_version: "1"
        include_local_lan: "disable"
        interface: "<your_own_value> (source system.interface.name)"
        ipv4_dns_server1: "<your_own_value>"
        ipv4_dns_server2: "<your_own_value>"
        ipv4_dns_server3: "<your_own_value>"
        ipv4_end_ip: "<your_own_value>"
        ipv4_exclude_range:
         -
            end_ip: "<your_own_value>"
            id:  "52"
            start_ip: "<your_own_value>"
        ipv4_name: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        ipv4_netmask: "<your_own_value>"
        ipv4_split_exclude: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        ipv4_split_include: "<your_own_value> (source firewall.address.name firewall.addrgrp.name)"
        ipv4_start_ip: "<your_own_value>"
        ipv4_wins_server1: "<your_own_value>"
        ipv4_wins_server2: "<your_own_value>"
        ipv6_dns_server1: "<your_own_value>"
        ipv6_dns_server2: "<your_own_value>"
        ipv6_dns_server3: "<your_own_value>"
        ipv6_end_ip: "<your_own_value>"
        ipv6_exclude_range:
         -
            end_ip: "<your_own_value>"
            id:  "67"
            start_ip: "<your_own_value>"
        ipv6_name: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
        ipv6_prefix: "70"
        ipv6_split_exclude: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
        ipv6_split_include: "<your_own_value> (source firewall.address6.name firewall.addrgrp6.name)"
        ipv6_start_ip: "<your_own_value>"
        keepalive: "74"
        keylife: "75"
        local_gw: "<your_own_value>"
        localid: "<your_own_value>"
        localid_type: "auto"
        mesh_selector_type: "disable"
        mode: "aggressive"
        mode_cfg: "disable"
        name: "default_name_82"
        nattraversal: "enable"
        negotiate_timeout: "84"
        peer: "<your_own_value> (source user.peer.name)"
        peergrp: "<your_own_value> (source user.peergrp.name)"
        peerid: "<your_own_value>"
        peertype: "any"
        ppk: "disable"
        ppk_identity: "<your_own_value>"
        ppk_secret: "<your_own_value>"
        priority: "92"
        proposal: "des-md5"
        psksecret: "<your_own_value>"
        psksecret_remote: "<your_own_value>"
        reauth: "disable"
        rekey: "enable"
        remote_gw: "<your_own_value>"
        remotegw_ddns: "<your_own_value>"
        rsa_signature_format: "pkcs1"
        save_password: "disable"
        send_cert_chain: "enable"
        signature_hash_alg: "sha1"
        split_include_service: "<your_own_value> (source firewall.service.group.name firewall.service.custom.name)"
        suite_b: "disable"
        type: "static"
        unity_support: "disable"
        usrgrp: "<your_own_value> (source user.group.name)"
        wizard_type: "custom"
        xauthtype: "disable"
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

    fos.debug('on')
    if 'https' in data and not data['https']:
        fos.https('off')
    else:
        fos.https('on')

    fos.login(host, username, password)


def filter_vpn_ipsec_phase1_data(json):
    option_list = ['acct_verify', 'add_gw_route', 'add_route',
                   'assign_ip', 'assign_ip_from', 'authmethod',
                   'authmethod_remote', 'authpasswd', 'authusr',
                   'authusrgrp', 'auto_negotiate', 'backup_gateway',
                   'banner', 'cert_id_validation', 'certificate',
                   'childless_ike', 'client_auto_negotiate', 'client_keep_alive',
                   'comments', 'dhgrp', 'digital_signature_auth',
                   'distance', 'dns_mode', 'domain',
                   'dpd', 'dpd_retrycount', 'dpd_retryinterval',
                   'eap', 'eap_identity', 'enforce_unique_id',
                   'forticlient_enforcement', 'fragmentation', 'fragmentation_mtu',
                   'group_authentication', 'group_authentication_secret', 'ha_sync_esp_seqno',
                   'idle_timeout', 'idle_timeoutinterval', 'ike_version',
                   'include_local_lan', 'interface', 'ipv4_dns_server1',
                   'ipv4_dns_server2', 'ipv4_dns_server3', 'ipv4_end_ip',
                   'ipv4_exclude_range', 'ipv4_name', 'ipv4_netmask',
                   'ipv4_split_exclude', 'ipv4_split_include', 'ipv4_start_ip',
                   'ipv4_wins_server1', 'ipv4_wins_server2', 'ipv6_dns_server1',
                   'ipv6_dns_server2', 'ipv6_dns_server3', 'ipv6_end_ip',
                   'ipv6_exclude_range', 'ipv6_name', 'ipv6_prefix',
                   'ipv6_split_exclude', 'ipv6_split_include', 'ipv6_start_ip',
                   'keepalive', 'keylife', 'local_gw',
                   'localid', 'localid_type', 'mesh_selector_type',
                   'mode', 'mode_cfg', 'name',
                   'nattraversal', 'negotiate_timeout', 'peer',
                   'peergrp', 'peerid', 'peertype',
                   'ppk', 'ppk_identity', 'ppk_secret',
                   'priority', 'proposal', 'psksecret',
                   'psksecret_remote', 'reauth', 'rekey',
                   'remote_gw', 'remotegw_ddns', 'rsa_signature_format',
                   'save_password', 'send_cert_chain', 'signature_hash_alg',
                   'split_include_service', 'suite_b', 'type',
                   'unity_support', 'usrgrp', 'wizard_type',
                   'xauthtype']
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


def vpn_ipsec_phase1(data, fos):
    vdom = data['vdom']
    state = data['state']
    vpn_ipsec_phase1_data = data['vpn_ipsec_phase1']
    filtered_data = underscore_to_hyphen(filter_vpn_ipsec_phase1_data(vpn_ipsec_phase1_data))

    if state == "present":
        return fos.set('vpn.ipsec',
                       'phase1',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('vpn.ipsec',
                          'phase1',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_vpn_ipsec(data, fos):

    if data['vpn_ipsec_phase1']:
        resp = vpn_ipsec_phase1(data, fos)

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
        "state": {"required": True, "type": "str",
                  "choices": ["present", "absent"]},
        "vpn_ipsec_phase1": {
            "required": False, "type": "dict",
            "options": {
                "acct_verify": {"required": False, "type": "str",
                                "choices": ["enable", "disable"]},
                "add_gw_route": {"required": False, "type": "str",
                                 "choices": ["enable", "disable"]},
                "add_route": {"required": False, "type": "str",
                              "choices": ["disable", "enable"]},
                "assign_ip": {"required": False, "type": "str",
                              "choices": ["disable", "enable"]},
                "assign_ip_from": {"required": False, "type": "str",
                                   "choices": ["range", "usrgrp", "dhcp",
                                               "name"]},
                "authmethod": {"required": False, "type": "str",
                               "choices": ["psk", "signature"]},
                "authmethod_remote": {"required": False, "type": "str",
                                      "choices": ["psk", "signature"]},
                "authpasswd": {"required": False, "type": "str"},
                "authusr": {"required": False, "type": "str"},
                "authusrgrp": {"required": False, "type": "str"},
                "auto_negotiate": {"required": False, "type": "str",
                                   "choices": ["enable", "disable"]},
                "backup_gateway": {"required": False, "type": "list",
                                   "options": {
                                       "address": {"required": True, "type": "str"}
                                   }},
                "banner": {"required": False, "type": "str"},
                "cert_id_validation": {"required": False, "type": "str",
                                       "choices": ["enable", "disable"]},
                "certificate": {"required": False, "type": "list",
                                "options": {
                                    "name": {"required": True, "type": "str"}
                                }},
                "childless_ike": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "client_auto_negotiate": {"required": False, "type": "str",
                                          "choices": ["disable", "enable"]},
                "client_keep_alive": {"required": False, "type": "str",
                                      "choices": ["disable", "enable"]},
                "comments": {"required": False, "type": "str"},
                "dhgrp": {"required": False, "type": "str",
                          "choices": ["1", "2", "5",
                                      "14", "15", "16",
                                      "17", "18", "19",
                                      "20", "21", "27",
                                      "28", "29", "30",
                                      "31"]},
                "digital_signature_auth": {"required": False, "type": "str",
                                           "choices": ["enable", "disable"]},
                "distance": {"required": False, "type": "int"},
                "dns_mode": {"required": False, "type": "str",
                             "choices": ["manual", "auto"]},
                "domain": {"required": False, "type": "str"},
                "dpd": {"required": False, "type": "str",
                        "choices": ["disable", "on-idle", "on-demand"]},
                "dpd_retrycount": {"required": False, "type": "int"},
                "dpd_retryinterval": {"required": False, "type": "str"},
                "eap": {"required": False, "type": "str",
                        "choices": ["enable", "disable"]},
                "eap_identity": {"required": False, "type": "str",
                                 "choices": ["use-id-payload", "send-request"]},
                "enforce_unique_id": {"required": False, "type": "str",
                                      "choices": ["disable", "keep-new", "keep-old"]},
                "forticlient_enforcement": {"required": False, "type": "str",
                                            "choices": ["enable", "disable"]},
                "fragmentation": {"required": False, "type": "str",
                                  "choices": ["enable", "disable"]},
                "fragmentation_mtu": {"required": False, "type": "int"},
                "group_authentication": {"required": False, "type": "str",
                                         "choices": ["enable", "disable"]},
                "group_authentication_secret": {"required": False, "type": "str"},
                "ha_sync_esp_seqno": {"required": False, "type": "str",
                                      "choices": ["enable", "disable"]},
                "idle_timeout": {"required": False, "type": "str",
                                 "choices": ["enable", "disable"]},
                "idle_timeoutinterval": {"required": False, "type": "int"},
                "ike_version": {"required": False, "type": "str",
                                "choices": ["1", "2"]},
                "include_local_lan": {"required": False, "type": "str",
                                      "choices": ["disable", "enable"]},
                "interface": {"required": False, "type": "str"},
                "ipv4_dns_server1": {"required": False, "type": "str"},
                "ipv4_dns_server2": {"required": False, "type": "str"},
                "ipv4_dns_server3": {"required": False, "type": "str"},
                "ipv4_end_ip": {"required": False, "type": "str"},
                "ipv4_exclude_range": {"required": False, "type": "list",
                                       "options": {
                                           "end_ip": {"required": False, "type": "str"},
                                           "id": {"required": True, "type": "int"},
                                           "start_ip": {"required": False, "type": "str"}
                                       }},
                "ipv4_name": {"required": False, "type": "str"},
                "ipv4_netmask": {"required": False, "type": "str"},
                "ipv4_split_exclude": {"required": False, "type": "str"},
                "ipv4_split_include": {"required": False, "type": "str"},
                "ipv4_start_ip": {"required": False, "type": "str"},
                "ipv4_wins_server1": {"required": False, "type": "str"},
                "ipv4_wins_server2": {"required": False, "type": "str"},
                "ipv6_dns_server1": {"required": False, "type": "str"},
                "ipv6_dns_server2": {"required": False, "type": "str"},
                "ipv6_dns_server3": {"required": False, "type": "str"},
                "ipv6_end_ip": {"required": False, "type": "str"},
                "ipv6_exclude_range": {"required": False, "type": "list",
                                       "options": {
                                           "end_ip": {"required": False, "type": "str"},
                                           "id": {"required": True, "type": "int"},
                                           "start_ip": {"required": False, "type": "str"}
                                       }},
                "ipv6_name": {"required": False, "type": "str"},
                "ipv6_prefix": {"required": False, "type": "int"},
                "ipv6_split_exclude": {"required": False, "type": "str"},
                "ipv6_split_include": {"required": False, "type": "str"},
                "ipv6_start_ip": {"required": False, "type": "str"},
                "keepalive": {"required": False, "type": "int"},
                "keylife": {"required": False, "type": "int"},
                "local_gw": {"required": False, "type": "str"},
                "localid": {"required": False, "type": "str"},
                "localid_type": {"required": False, "type": "str",
                                 "choices": ["auto", "fqdn", "user-fqdn",
                                             "keyid", "address", "asn1dn"]},
                "mesh_selector_type": {"required": False, "type": "str",
                                       "choices": ["disable", "subnet", "host"]},
                "mode": {"required": False, "type": "str",
                         "choices": ["aggressive", "main"]},
                "mode_cfg": {"required": False, "type": "str",
                             "choices": ["disable", "enable"]},
                "name": {"required": True, "type": "str"},
                "nattraversal": {"required": False, "type": "str",
                                 "choices": ["enable", "disable", "forced"]},
                "negotiate_timeout": {"required": False, "type": "int"},
                "peer": {"required": False, "type": "str"},
                "peergrp": {"required": False, "type": "str"},
                "peerid": {"required": False, "type": "str"},
                "peertype": {"required": False, "type": "str",
                             "choices": ["any", "one", "dialup",
                                         "peer", "peergrp"]},
                "ppk": {"required": False, "type": "str",
                        "choices": ["disable", "allow", "require"]},
                "ppk_identity": {"required": False, "type": "str"},
                "ppk_secret": {"required": False, "type": "str"},
                "priority": {"required": False, "type": "int"},
                "proposal": {"required": False, "type": "str",
                             "choices": ["des-md5", "des-sha1", "des-sha256",
                                         "des-sha384", "des-sha512"]},
                "psksecret": {"required": False, "type": "str"},
                "psksecret_remote": {"required": False, "type": "str"},
                "reauth": {"required": False, "type": "str",
                           "choices": ["disable", "enable"]},
                "rekey": {"required": False, "type": "str",
                          "choices": ["enable", "disable"]},
                "remote_gw": {"required": False, "type": "str"},
                "remotegw_ddns": {"required": False, "type": "str"},
                "rsa_signature_format": {"required": False, "type": "str",
                                         "choices": ["pkcs1", "pss"]},
                "save_password": {"required": False, "type": "str",
                                  "choices": ["disable", "enable"]},
                "send_cert_chain": {"required": False, "type": "str",
                                    "choices": ["enable", "disable"]},
                "signature_hash_alg": {"required": False, "type": "str",
                                       "choices": ["sha1", "sha2-256", "sha2-384",
                                                   "sha2-512"]},
                "split_include_service": {"required": False, "type": "str"},
                "suite_b": {"required": False, "type": "str",
                            "choices": ["disable", "suite-b-gcm-128", "suite-b-gcm-256"]},
                "type": {"required": False, "type": "str",
                         "choices": ["static", "dynamic", "ddns"]},
                "unity_support": {"required": False, "type": "str",
                                  "choices": ["disable", "enable"]},
                "usrgrp": {"required": False, "type": "str"},
                "wizard_type": {"required": False, "type": "str",
                                "choices": ["custom", "dialup-forticlient", "dialup-ios",
                                            "dialup-android", "dialup-windows", "dialup-cisco",
                                            "static-fortigate", "dialup-fortigate", "static-cisco",
                                            "dialup-cisco-fw"]},
                "xauthtype": {"required": False, "type": "str",
                              "choices": ["disable", "client", "pap",
                                          "chap", "auto"]}

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

            is_error, has_changed, result = fortios_vpn_ipsec(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_vpn_ipsec(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
