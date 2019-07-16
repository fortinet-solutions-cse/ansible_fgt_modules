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
module: fortios_voip_profile
short_description: Configure VoIP profiles in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS device by allowing the
      user to set and modify voip feature and profile category.
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
    voip_profile:
        description:
            - Configure VoIP profiles.
        default: null
        type: dict
        suboptions:
            comment:
                description:
                    - Comment.
            name:
                description:
                    - Profile name.
                required: true
            sccp:
                description:
                    - SCCP.
                suboptions:
                    block_mcast:
                        description:
                            - Enable/disable block multicast RTP connections.
                        choices:
                            - disable
                            - enable
                    log_call_summary:
                        description:
                            - Enable/disable log summary of SCCP calls.
                        choices:
                            - disable
                            - enable
                    log_violations:
                        description:
                            - Enable/disable logging of SCCP violations.
                        choices:
                            - disable
                            - enable
                    max_calls:
                        description:
                            - Maximum calls per minute per SCCP client (max 65535).
                    status:
                        description:
                            - Enable/disable SCCP.
                        choices:
                            - disable
                            - enable
                    verify_header:
                        description:
                            - Enable/disable verify SCCP header content.
                        choices:
                            - disable
                            - enable
            sip:
                description:
                    - SIP.
                suboptions:
                    ack_rate:
                        description:
                            - ACK request rate limit (per second, per policy).
                    block_ack:
                        description:
                            - Enable/disable block ACK requests.
                        choices:
                            - disable
                            - enable
                    block_bye:
                        description:
                            - Enable/disable block BYE requests.
                        choices:
                            - disable
                            - enable
                    block_cancel:
                        description:
                            - Enable/disable block CANCEL requests.
                        choices:
                            - disable
                            - enable
                    block_geo_red_options:
                        description:
                            - Enable/disable block OPTIONS requests, but OPTIONS requests still notify for redundancy.
                        choices:
                            - disable
                            - enable
                    block_info:
                        description:
                            - Enable/disable block INFO requests.
                        choices:
                            - disable
                            - enable
                    block_invite:
                        description:
                            - Enable/disable block INVITE requests.
                        choices:
                            - disable
                            - enable
                    block_long_lines:
                        description:
                            - Enable/disable block requests with headers exceeding max_line_length.
                        choices:
                            - disable
                            - enable
                    block_message:
                        description:
                            - Enable/disable block MESSAGE requests.
                        choices:
                            - disable
                            - enable
                    block_notify:
                        description:
                            - Enable/disable block NOTIFY requests.
                        choices:
                            - disable
                            - enable
                    block_options:
                        description:
                            - Enable/disable block OPTIONS requests and no OPTIONS as notifying message for redundancy either.
                        choices:
                            - disable
                            - enable
                    block_prack:
                        description:
                            - Enable/disable block prack requests.
                        choices:
                            - disable
                            - enable
                    block_publish:
                        description:
                            - Enable/disable block PUBLISH requests.
                        choices:
                            - disable
                            - enable
                    block_refer:
                        description:
                            - Enable/disable block REFER requests.
                        choices:
                            - disable
                            - enable
                    block_register:
                        description:
                            - Enable/disable block REGISTER requests.
                        choices:
                            - disable
                            - enable
                    block_subscribe:
                        description:
                            - Enable/disable block SUBSCRIBE requests.
                        choices:
                            - disable
                            - enable
                    block_unknown:
                        description:
                            - Block unrecognized SIP requests (enabled by default).
                        choices:
                            - disable
                            - enable
                    block_update:
                        description:
                            - Enable/disable block UPDATE requests.
                        choices:
                            - disable
                            - enable
                    bye_rate:
                        description:
                            - BYE request rate limit (per second, per policy).
                    call_keepalive:
                        description:
                            - Continue tracking calls with no RTP for this many minutes.
                    cancel_rate:
                        description:
                            - CANCEL request rate limit (per second, per policy).
                    contact_fixup:
                        description:
                            - "Fixup contact anyway even if contact's IP:port doesn't match session's IP:port."
                        choices:
                            - disable
                            - enable
                    hnt_restrict_source_ip:
                        description:
                            - Enable/disable restrict RTP source IP to be the same as SIP source IP when HNT is enabled.
                        choices:
                            - disable
                            - enable
                    hosted_nat_traversal:
                        description:
                            - Hosted NAT Traversal (HNT).
                        choices:
                            - disable
                            - enable
                    info_rate:
                        description:
                            - INFO request rate limit (per second, per policy).
                    invite_rate:
                        description:
                            - INVITE request rate limit (per second, per policy).
                    ips_rtp:
                        description:
                            - Enable/disable allow IPS on RTP.
                        choices:
                            - disable
                            - enable
                    log_call_summary:
                        description:
                            - Enable/disable logging of SIP call summary.
                        choices:
                            - disable
                            - enable
                    log_violations:
                        description:
                            - Enable/disable logging of SIP violations.
                        choices:
                            - disable
                            - enable
                    malformed_header_allow:
                        description:
                            - Action for malformed Allow header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_call_id:
                        description:
                            - Action for malformed Call_ID header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_contact:
                        description:
                            - Action for malformed Contact header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_content_length:
                        description:
                            - Action for malformed Content_Length header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_content_type:
                        description:
                            - Action for malformed Content_Type header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_cseq:
                        description:
                            - Action for malformed CSeq header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_expires:
                        description:
                            - Action for malformed Expires header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_from:
                        description:
                            - Action for malformed From header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_max_forwards:
                        description:
                            - Action for malformed Max_Forwards header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_p_asserted_identity:
                        description:
                            - Action for malformed P_Asserted_Identity header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_rack:
                        description:
                            - Action for malformed RAck header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_record_route:
                        description:
                            - Action for malformed Record_Route header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_route:
                        description:
                            - Action for malformed Route header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_rseq:
                        description:
                            - Action for malformed RSeq header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_a:
                        description:
                            - Action for malformed SDP a line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_b:
                        description:
                            - Action for malformed SDP b line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_c:
                        description:
                            - Action for malformed SDP c line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_i:
                        description:
                            - Action for malformed SDP i line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_k:
                        description:
                            - Action for malformed SDP k line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_m:
                        description:
                            - Action for malformed SDP m line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_o:
                        description:
                            - Action for malformed SDP o line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_r:
                        description:
                            - Action for malformed SDP r line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_s:
                        description:
                            - Action for malformed SDP s line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_t:
                        description:
                            - Action for malformed SDP t line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_v:
                        description:
                            - Action for malformed SDP v line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_sdp_z:
                        description:
                            - Action for malformed SDP z line.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_to:
                        description:
                            - Action for malformed To header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_header_via:
                        description:
                            - Action for malformed VIA header.
                        choices:
                            - discard
                            - pass
                            - respond
                    malformed_request_line:
                        description:
                            - Action for malformed request line.
                        choices:
                            - discard
                            - pass
                            - respond
                    max_body_length:
                        description:
                            - Maximum SIP message body length (0 meaning no limit).
                    max_dialogs:
                        description:
                            - Maximum number of concurrent calls/dialogs (per policy).
                    max_idle_dialogs:
                        description:
                            - Maximum number established but idle dialogs to retain (per policy).
                    max_line_length:
                        description:
                            - Maximum SIP header line length (78_4096).
                    message_rate:
                        description:
                            - MESSAGE request rate limit (per second, per policy).
                    nat_trace:
                        description:
                            - Enable/disable preservation of original IP in SDP i line.
                        choices:
                            - disable
                            - enable
                    no_sdp_fixup:
                        description:
                            - Enable/disable no SDP fix_up.
                        choices:
                            - disable
                            - enable
                    notify_rate:
                        description:
                            - NOTIFY request rate limit (per second, per policy).
                    open_contact_pinhole:
                        description:
                            - Enable/disable open pinhole for non_REGISTER Contact port.
                        choices:
                            - disable
                            - enable
                    open_record_route_pinhole:
                        description:
                            - Enable/disable open pinhole for Record_Route port.
                        choices:
                            - disable
                            - enable
                    open_register_pinhole:
                        description:
                            - Enable/disable open pinhole for REGISTER Contact port.
                        choices:
                            - disable
                            - enable
                    open_via_pinhole:
                        description:
                            - Enable/disable open pinhole for Via port.
                        choices:
                            - disable
                            - enable
                    options_rate:
                        description:
                            - OPTIONS request rate limit (per second, per policy).
                    prack_rate:
                        description:
                            - PRACK request rate limit (per second, per policy).
                    preserve_override:
                        description:
                            - "Override i line to preserve original IPS (default: append)."
                        choices:
                            - disable
                            - enable
                    provisional_invite_expiry_time:
                        description:
                            - Expiry time for provisional INVITE (10 _ 3600 sec).
                    publish_rate:
                        description:
                            - PUBLISH request rate limit (per second, per policy).
                    refer_rate:
                        description:
                            - REFER request rate limit (per second, per policy).
                    register_contact_trace:
                        description:
                            - Enable/disable trace original IP/port within the contact header of REGISTER requests.
                        choices:
                            - disable
                            - enable
                    register_rate:
                        description:
                            - REGISTER request rate limit (per second, per policy).
                    rfc2543_branch:
                        description:
                            - Enable/disable support via branch compliant with RFC 2543.
                        choices:
                            - disable
                            - enable
                    rtp:
                        description:
                            - Enable/disable create pinholes for RTP traffic to traverse firewall.
                        choices:
                            - disable
                            - enable
                    ssl_algorithm:
                        description:
                            - Relative strength of encryption algorithms accepted in negotiation.
                        choices:
                            - high
                            - medium
                            - low
                    ssl_auth_client:
                        description:
                            - Require a client certificate and authenticate it with the peer/peergrp. Source user.peer.name user.peergrp.name.
                    ssl_auth_server:
                        description:
                            - Authenticate the server's certificate with the peer/peergrp. Source user.peer.name user.peergrp.name.
                    ssl_client_certificate:
                        description:
                            - Name of Certificate to offer to server if requested. Source vpn.certificate.local.name.
                    ssl_client_renegotiation:
                        description:
                            - Allow/block client renegotiation by server.
                        choices:
                            - allow
                            - deny
                            - secure
                    ssl_max_version:
                        description:
                            - Highest SSL/TLS version to negotiate.
                        choices:
                            - ssl-3.0
                            - tls-1.0
                            - tls-1.1
                            - tls-1.2
                    ssl_min_version:
                        description:
                            - Lowest SSL/TLS version to negotiate.
                        choices:
                            - ssl-3.0
                            - tls-1.0
                            - tls-1.1
                            - tls-1.2
                    ssl_mode:
                        description:
                            - SSL/TLS mode for encryption & decryption of traffic.
                        choices:
                            - off
                            - full
                    ssl_pfs:
                        description:
                            - SSL Perfect Forward Secrecy.
                        choices:
                            - require
                            - deny
                            - allow
                    ssl_send_empty_frags:
                        description:
                            - Send empty fragments to avoid attack on CBC IV (SSL 3.0 & TLS 1.0 only).
                        choices:
                            - enable
                            - disable
                    ssl_server_certificate:
                        description:
                            - Name of Certificate return to the client in every SSL connection. Source vpn.certificate.local.name.
                    status:
                        description:
                            - Enable/disable SIP.
                        choices:
                            - disable
                            - enable
                    strict_register:
                        description:
                            - Enable/disable only allow the registrar to connect.
                        choices:
                            - disable
                            - enable
                    subscribe_rate:
                        description:
                            - SUBSCRIBE request rate limit (per second, per policy).
                    unknown_header:
                        description:
                            - Action for unknown SIP header.
                        choices:
                            - discard
                            - pass
                            - respond
                    update_rate:
                        description:
                            - UPDATE request rate limit (per second, per policy).
'''

EXAMPLES = '''
- hosts: localhost
  vars:
   host: "192.168.122.40"
   username: "admin"
   password: ""
   vdom: "root"
  tasks:
  - name: Configure VoIP profiles.
    fortios_voip_profile:
      host:  "{{ host }}"
      username: "{{ username }}"
      password: "{{ password }}"
      vdom:  "{{ vdom }}"
      https: "False"
      state: "present"
      voip_profile:
        comment: "Comment."
        name: "default_name_4"
        sccp:
            block_mcast: "disable"
            log_call_summary: "disable"
            log_violations: "disable"
            max_calls: "9"
            status: "disable"
            verify_header: "disable"
        sip:
            ack_rate: "13"
            block_ack: "disable"
            block_bye: "disable"
            block_cancel: "disable"
            block_geo_red_options: "disable"
            block_info: "disable"
            block_invite: "disable"
            block_long_lines: "disable"
            block_message: "disable"
            block_notify: "disable"
            block_options: "disable"
            block_prack: "disable"
            block_publish: "disable"
            block_refer: "disable"
            block_register: "disable"
            block_subscribe: "disable"
            block_unknown: "disable"
            block_update: "disable"
            bye_rate: "31"
            call_keepalive: "32"
            cancel_rate: "33"
            contact_fixup: "disable"
            hnt_restrict_source_ip: "disable"
            hosted_nat_traversal: "disable"
            info_rate: "37"
            invite_rate: "38"
            ips_rtp: "disable"
            log_call_summary: "disable"
            log_violations: "disable"
            malformed_header_allow: "discard"
            malformed_header_call_id: "discard"
            malformed_header_contact: "discard"
            malformed_header_content_length: "discard"
            malformed_header_content_type: "discard"
            malformed_header_cseq: "discard"
            malformed_header_expires: "discard"
            malformed_header_from: "discard"
            malformed_header_max_forwards: "discard"
            malformed_header_p_asserted_identity: "discard"
            malformed_header_rack: "discard"
            malformed_header_record_route: "discard"
            malformed_header_route: "discard"
            malformed_header_rseq: "discard"
            malformed_header_sdp_a: "discard"
            malformed_header_sdp_b: "discard"
            malformed_header_sdp_c: "discard"
            malformed_header_sdp_i: "discard"
            malformed_header_sdp_k: "discard"
            malformed_header_sdp_m: "discard"
            malformed_header_sdp_o: "discard"
            malformed_header_sdp_r: "discard"
            malformed_header_sdp_s: "discard"
            malformed_header_sdp_t: "discard"
            malformed_header_sdp_v: "discard"
            malformed_header_sdp_z: "discard"
            malformed_header_to: "discard"
            malformed_header_via: "discard"
            malformed_request_line: "discard"
            max_body_length: "71"
            max_dialogs: "72"
            max_idle_dialogs: "73"
            max_line_length: "74"
            message_rate: "75"
            nat_trace: "disable"
            no_sdp_fixup: "disable"
            notify_rate: "78"
            open_contact_pinhole: "disable"
            open_record_route_pinhole: "disable"
            open_register_pinhole: "disable"
            open_via_pinhole: "disable"
            options_rate: "83"
            prack_rate: "84"
            preserve_override: "disable"
            provisional_invite_expiry_time: "86"
            publish_rate: "87"
            refer_rate: "88"
            register_contact_trace: "disable"
            register_rate: "90"
            rfc2543_branch: "disable"
            rtp: "disable"
            ssl_algorithm: "high"
            ssl_auth_client: "<your_own_value> (source user.peer.name user.peergrp.name)"
            ssl_auth_server: "<your_own_value> (source user.peer.name user.peergrp.name)"
            ssl_client_certificate: "<your_own_value> (source vpn.certificate.local.name)"
            ssl_client_renegotiation: "allow"
            ssl_max_version: "ssl-3.0"
            ssl_min_version: "ssl-3.0"
            ssl_mode: "off"
            ssl_pfs: "require"
            ssl_send_empty_frags: "enable"
            ssl_server_certificate: "<your_own_value> (source vpn.certificate.local.name)"
            status: "disable"
            strict_register: "disable"
            subscribe_rate: "106"
            unknown_header: "discard"
            update_rate: "108"
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


def filter_voip_profile_data(json):
    option_list = ['comment', 'name', 'sccp',
                   'sip']
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


def voip_profile(data, fos):
    vdom = data['vdom']
    state = data['state']
    voip_profile_data = data['voip_profile']
    filtered_data = underscore_to_hyphen(filter_voip_profile_data(voip_profile_data))

    if state == "present":
        return fos.set('voip',
                       'profile',
                       data=filtered_data,
                       vdom=vdom)

    elif state == "absent":
        return fos.delete('voip',
                          'profile',
                          mkey=filtered_data['name'],
                          vdom=vdom)


def is_successful_status(status):
    return status['status'] == "success" or \
        status['http_method'] == "DELETE" and status['http_status'] == 404


def fortios_voip(data, fos):

    if data['voip_profile']:
        resp = voip_profile(data, fos)

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
        "voip_profile": {
            "required": False, "type": "dict",
            "options": {
                "comment": {"required": False, "type": "str"},
                "name": {"required": True, "type": "str"},
                "sccp": {"required": False, "type": "dict",
                         "options": {
                             "block_mcast": {"required": False, "type": "str",
                                             "choices": ["disable", "enable"]},
                             "log_call_summary": {"required": False, "type": "str",
                                                  "choices": ["disable", "enable"]},
                             "log_violations": {"required": False, "type": "str",
                                                "choices": ["disable", "enable"]},
                             "max_calls": {"required": False, "type": "int"},
                             "status": {"required": False, "type": "str",
                                        "choices": ["disable", "enable"]},
                             "verify_header": {"required": False, "type": "str",
                                               "choices": ["disable", "enable"]}
                         }},
                "sip": {"required": False, "type": "dict",
                        "options": {
                            "ack_rate": {"required": False, "type": "int"},
                            "block_ack": {"required": False, "type": "str",
                                          "choices": ["disable", "enable"]},
                            "block_bye": {"required": False, "type": "str",
                                          "choices": ["disable", "enable"]},
                            "block_cancel": {"required": False, "type": "str",
                                             "choices": ["disable", "enable"]},
                            "block_geo_red_options": {"required": False, "type": "str",
                                                      "choices": ["disable", "enable"]},
                            "block_info": {"required": False, "type": "str",
                                           "choices": ["disable", "enable"]},
                            "block_invite": {"required": False, "type": "str",
                                             "choices": ["disable", "enable"]},
                            "block_long_lines": {"required": False, "type": "str",
                                                 "choices": ["disable", "enable"]},
                            "block_message": {"required": False, "type": "str",
                                              "choices": ["disable", "enable"]},
                            "block_notify": {"required": False, "type": "str",
                                             "choices": ["disable", "enable"]},
                            "block_options": {"required": False, "type": "str",
                                              "choices": ["disable", "enable"]},
                            "block_prack": {"required": False, "type": "str",
                                            "choices": ["disable", "enable"]},
                            "block_publish": {"required": False, "type": "str",
                                              "choices": ["disable", "enable"]},
                            "block_refer": {"required": False, "type": "str",
                                            "choices": ["disable", "enable"]},
                            "block_register": {"required": False, "type": "str",
                                               "choices": ["disable", "enable"]},
                            "block_subscribe": {"required": False, "type": "str",
                                                "choices": ["disable", "enable"]},
                            "block_unknown": {"required": False, "type": "str",
                                              "choices": ["disable", "enable"]},
                            "block_update": {"required": False, "type": "str",
                                             "choices": ["disable", "enable"]},
                            "bye_rate": {"required": False, "type": "int"},
                            "call_keepalive": {"required": False, "type": "int"},
                            "cancel_rate": {"required": False, "type": "int"},
                            "contact_fixup": {"required": False, "type": "str",
                                              "choices": ["disable", "enable"]},
                            "hnt_restrict_source_ip": {"required": False, "type": "str",
                                                       "choices": ["disable", "enable"]},
                            "hosted_nat_traversal": {"required": False, "type": "str",
                                                     "choices": ["disable", "enable"]},
                            "info_rate": {"required": False, "type": "int"},
                            "invite_rate": {"required": False, "type": "int"},
                            "ips_rtp": {"required": False, "type": "str",
                                        "choices": ["disable", "enable"]},
                            "log_call_summary": {"required": False, "type": "str",
                                                 "choices": ["disable", "enable"]},
                            "log_violations": {"required": False, "type": "str",
                                               "choices": ["disable", "enable"]},
                            "malformed_header_allow": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_call_id": {"required": False, "type": "str",
                                                         "choices": ["discard", "pass", "respond"]},
                            "malformed_header_contact": {"required": False, "type": "str",
                                                         "choices": ["discard", "pass", "respond"]},
                            "malformed_header_content_length": {"required": False, "type": "str",
                                                                "choices": ["discard", "pass", "respond"]},
                            "malformed_header_content_type": {"required": False, "type": "str",
                                                              "choices": ["discard", "pass", "respond"]},
                            "malformed_header_cseq": {"required": False, "type": "str",
                                                      "choices": ["discard", "pass", "respond"]},
                            "malformed_header_expires": {"required": False, "type": "str",
                                                         "choices": ["discard", "pass", "respond"]},
                            "malformed_header_from": {"required": False, "type": "str",
                                                      "choices": ["discard", "pass", "respond"]},
                            "malformed_header_max_forwards": {"required": False, "type": "str",
                                                              "choices": ["discard", "pass", "respond"]},
                            "malformed_header_p_asserted_identity": {"required": False, "type": "str",
                                                                     "choices": ["discard", "pass", "respond"]},
                            "malformed_header_rack": {"required": False, "type": "str",
                                                      "choices": ["discard", "pass", "respond"]},
                            "malformed_header_record_route": {"required": False, "type": "str",
                                                              "choices": ["discard", "pass", "respond"]},
                            "malformed_header_route": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_rseq": {"required": False, "type": "str",
                                                      "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_a": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_b": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_c": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_i": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_k": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_m": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_o": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_r": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_s": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_t": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_v": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_sdp_z": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "malformed_header_to": {"required": False, "type": "str",
                                                    "choices": ["discard", "pass", "respond"]},
                            "malformed_header_via": {"required": False, "type": "str",
                                                     "choices": ["discard", "pass", "respond"]},
                            "malformed_request_line": {"required": False, "type": "str",
                                                       "choices": ["discard", "pass", "respond"]},
                            "max_body_length": {"required": False, "type": "int"},
                            "max_dialogs": {"required": False, "type": "int"},
                            "max_idle_dialogs": {"required": False, "type": "int"},
                            "max_line_length": {"required": False, "type": "int"},
                            "message_rate": {"required": False, "type": "int"},
                            "nat_trace": {"required": False, "type": "str",
                                          "choices": ["disable", "enable"]},
                            "no_sdp_fixup": {"required": False, "type": "str",
                                             "choices": ["disable", "enable"]},
                            "notify_rate": {"required": False, "type": "int"},
                            "open_contact_pinhole": {"required": False, "type": "str",
                                                     "choices": ["disable", "enable"]},
                            "open_record_route_pinhole": {"required": False, "type": "str",
                                                          "choices": ["disable", "enable"]},
                            "open_register_pinhole": {"required": False, "type": "str",
                                                      "choices": ["disable", "enable"]},
                            "open_via_pinhole": {"required": False, "type": "str",
                                                 "choices": ["disable", "enable"]},
                            "options_rate": {"required": False, "type": "int"},
                            "prack_rate": {"required": False, "type": "int"},
                            "preserve_override": {"required": False, "type": "str",
                                                  "choices": ["disable", "enable"]},
                            "provisional_invite_expiry_time": {"required": False, "type": "int"},
                            "publish_rate": {"required": False, "type": "int"},
                            "refer_rate": {"required": False, "type": "int"},
                            "register_contact_trace": {"required": False, "type": "str",
                                                       "choices": ["disable", "enable"]},
                            "register_rate": {"required": False, "type": "int"},
                            "rfc2543_branch": {"required": False, "type": "str",
                                               "choices": ["disable", "enable"]},
                            "rtp": {"required": False, "type": "str",
                                    "choices": ["disable", "enable"]},
                            "ssl_algorithm": {"required": False, "type": "str",
                                              "choices": ["high", "medium", "low"]},
                            "ssl_auth_client": {"required": False, "type": "str"},
                            "ssl_auth_server": {"required": False, "type": "str"},
                            "ssl_client_certificate": {"required": False, "type": "str"},
                            "ssl_client_renegotiation": {"required": False, "type": "str",
                                                         "choices": ["allow", "deny", "secure"]},
                            "ssl_max_version": {"required": False, "type": "str",
                                                "choices": ["ssl-3.0", "tls-1.0", "tls-1.1",
                                                            "tls-1.2"]},
                            "ssl_min_version": {"required": False, "type": "str",
                                                "choices": ["ssl-3.0", "tls-1.0", "tls-1.1",
                                                            "tls-1.2"]},
                            "ssl_mode": {"required": False, "type": "str",
                                         "choices": ["off", "full"]},
                            "ssl_pfs": {"required": False, "type": "str",
                                        "choices": ["require", "deny", "allow"]},
                            "ssl_send_empty_frags": {"required": False, "type": "str",
                                                     "choices": ["enable", "disable"]},
                            "ssl_server_certificate": {"required": False, "type": "str"},
                            "status": {"required": False, "type": "str",
                                       "choices": ["disable", "enable"]},
                            "strict_register": {"required": False, "type": "str",
                                                "choices": ["disable", "enable"]},
                            "subscribe_rate": {"required": False, "type": "int"},
                            "unknown_header": {"required": False, "type": "str",
                                               "choices": ["discard", "pass", "respond"]},
                            "update_rate": {"required": False, "type": "int"}
                        }}

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

            is_error, has_changed, result = fortios_voip(module.params, fos)
        else:
            module.fail_json(**FAIL_SOCKET_MSG)
    else:
        try:
            from fortiosapi import FortiOSAPI
        except ImportError:
            module.fail_json(msg="fortiosapi module is required")

        fos = FortiOSAPI()

        login(module.params, fos)
        is_error, has_changed, result = fortios_voip(module.params, fos)
        fos.logout()

    if not is_error:
        module.exit_json(changed=has_changed, meta=result)
    else:
        module.fail_json(msg="Error in repo", meta=result)


if __name__ == '__main__':
    main()
