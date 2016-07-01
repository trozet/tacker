# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# All Rights Reserved.
#
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Tim Rozet, Red Hat Inc.
# shamelessly many codes are stolen from gbp simplechain_driver.py

import sys
import time
import yaml
import requests
import json
import re
import copy

from keystoneclient.v2_0 import client as ks_client
from oslo_config import cfg

from tacker.common import exceptions
from tacker.common import log
from tacker.openstack.common import jsonutils
from tacker.openstack.common import log as logging
from tacker.vm.drivers import abstract_driver
from tacker.common import exceptions


LOG = logging.getLogger(__name__)
CONF = cfg.CONF

OPTS = [
    cfg.StrOpt('ip',
               default='127.0.0.1',
               help=_("OpenDaylight Controller address")),
    cfg.IntOpt('port',
               default=8080,
               help=_("OpenDaylight REST Port")),
    cfg.StrOpt('username',
               default='admin',
               help=_("OpenDaylight username")),
    cfg.StrOpt('password',
               default='admin',
               help=_("OpenDaylight password")),
]
CONF.register_opts(OPTS, group='sfc_opendaylight')


class ODLSFCreateFailed(exceptions.TackerException):
    message = _('ODL SFs could not be created')


class ODLSFFCreateFailed(exceptions.TackerException):
    message = _('ODL SFFs could not be created')


class ODLShowNetworkFailed(exceptions.TackerException):
    message = _('ODL Failed to dump network topology')


class ODLSFPCreateFailed(exceptions.TackerException):
    message = _('ODL SFP could not be created')


class ODLSFCCreateFailed(exceptions.TackerException):
    message = _('ODL SFC could not be created')


class ODLRSPCreateFailed(exceptions.TackerException):
    message = _('ODL RSP could not be created')


class ODLRESTFailed(exceptions.TackerException):
    message = _('REST returned %(status_code)')


class ODLRSPDeleteFailed(exceptions.TackerException):
    message = _('ODL RSP could not be deleted')


class DeviceOpenDaylight():

    """OpenDaylight driver of hosting device."""

    def __init__(self):
        if 'opendaylight' in cfg.CONF.sfc.infra_driver:
            self.odl_ip = cfg.CONF.sfc_opendaylight.ip
            self.odl_port = cfg.CONF.sfc_opendaylight.port
            self.username = cfg.CONF.sfc_opendaylight.username
            self.password = cfg.CONF.sfc_opendaylight.password
        else:
            LOG.warn(_('Unable to find opendaylight config in conf file'
                       'but opendaylight driver is loaded...'))
        self.sff_counter = 1
        self.config_sf_url = 'restconf/config/service-function:service-functions/service-function/{}/'
        self.config_sff_url = 'restconf/config/service-function-forwarder:service-function-forwarders/' \
                              'service-function-forwarder/{}/'
        self.config_sfc_url = 'restconf/config/service-function-chain:service-function-chains/' \
                              'service-function-chain/{}/'
        self.config_sfp_url = 'restconf/config/service-function-path:service-function-paths/service-function-path/{}'

    def get_type(self):
        return 'opendaylight'

    def get_name(self):
        return 'opendaylight'

    def get_description(self):
        return 'OpenDaylight infra driver'

    @log.log
    def send_rest(self, data, rest_type, url):
        full_url = 'http://' + self.odl_ip + ':' + str(self.odl_port) + '/' + url
        rest_call = getattr(requests, rest_type)
        if data is None:
            r = rest_call(full_url, stream=False, auth=(self.username, self.password))
        else:
            r = rest_call(full_url, data=json.dumps(data), headers={'content-type': 'application/json'},
                          stream=False, auth=(self.username, self.password))
        LOG.debug(_('rest call response: %s'), r)
        return r

    @log.log
    def list_network_topology(self):
        url = 'restconf/operational/network-topology:network-topology/'
        network = self.send_rest(None, 'get', url)
        return network

    @log.log
    def get_odl_sff(self):
        url = 'restconf/config/service-function-forwarder:service-function-forwarders/'
        sff_response = self.send_rest(None, 'get', url)
        return sff_response

    @log.log
    def create_odl_sff(self, sff_json):
        sff_name = sff_json['service-function-forwarder'][0]['name']
        sff_result = self.send_rest(sff_json, 'put', self.config_sff_url.format(sff_name))
        return sff_result

    @log.log
    def update_odl_sff(self, sff_json):
        sff_result = self.send_rest(sff_json, 'put', self.config_sff_url)
        return sff_result

    @log.log
    def delete_odl_sff(self, sff_json):
        sff_result = self.send_rest(sff_json, 'delete', self.config_sff_url)
        return sff_result

    @log.log
    def create_odl_sfs(self, sfs_json):
        sf_name = sfs_json['service-function'][0]['name']
        sfs_result = self.send_rest(sfs_json, 'put', self.config_sf_url.format(sf_name))
        return sfs_result

    @log.log
    def update_odl_sfs(self, sfs_json):
        sfs_result = self.send_rest(sfs_json, 'put', self.config_sf_url)
        return sfs_result

    @log.log
    def delete_odl_sfs(self, sfs_json):
        sfs_result = self.send_rest(sfs_json, 'delete', self.config_sf_url)
        return sfs_result

    @log.log
    def create_odl_sfc(self, sfc_json):
        sfc_name = sfc_json['service-function-chain'][0]['name']
        sfc_result = self.send_rest(sfc_json, 'put', self.config_sfc_url.format(sfc_name))
        return sfc_result

    @log.log
    def update_odl_sfc(self, sfc_json):
        sfc_result = self.send_rest(sfc_json, 'put', self.config_sfc_url)
        return sfc_result

    @log.log
    def delete_odl_sfc(self, sfc_json):
        sfc_result = self.send_rest(sfc_json, 'delete', self.config_sfc_url)
        return sfc_result

    @log.log
    def create_odl_sfp(self, sfp_json):
        sfp_name = sfp_json['service-function-path'][0]['name']
        sfp_result = self.send_rest(sfp_json, 'put', self.config_sfp_url.format(sfp_name))
        return sfp_result

    @log.log
    def update_odl_sfp(self, sfp_json):
        sfp_result = self.send_rest(sfp_json, 'put', self.config_sfp_url)
        return sfp_result

    @log.log
    def delete_odl_sfp(self, sfp_json):
        sfp_result = self.send_rest(sfp_json, 'delete', self.config_sfp_url)
        return sfp_result

    @log.log
    def create_odl_rsp(self, rsp_json):
        url = 'restconf/operations/rendered-service-path:create-rendered-path'
        rsp_result = self.send_rest(rsp_json, 'post', url)
        return rsp_result

    @log.log
    def delete_odl_rsp(self, rsp_json):
        url = 'restconf/operations/rendered-service-path:delete-rendered-path/'
        rsp_result = self.send_rest(rsp_json, 'post', url)
        return rsp_result

    @log.log
    def create_sfc(self, sfc_dict, vnf_dict):
        sfc_id = sfc_dict['id']
        dp_loc = 'sf-data-plane-locator'
        sfs_json = dict()
        sf_net_map = dict()
        # Required info for ODL REST call
        # For now assume vxlan and nsh aware
        for sf in sfc_dict['chain']:
            sf_json = dict()
            sf_json[dp_loc] = list()
            dp_loc_dict = dict()
            sf_id = sf
            sf_json['name'] = vnf_dict[sf]['name']
            dp_loc_dict['name'] = vnf_dict[sf]['name']+'-dpl'
            dp_loc_dict['ip'] = vnf_dict[sf]['ip']

            # trozet FIXME right now we hardcode 6633
            # if 'port' in sfc_dict['attributes'][sf].keys():
            # dp_loc_dict['port'] = sfc_dict['attributes'][sf]['port']
            # else:
            dp_loc_dict['port'] = '6633'

            dp_loc_dict['transport'] = 'service-locator:vxlan-gpe'
            # trozet how do we get SFF?
            # may need to ask ODL to find OVS attached to this VNF
            # then create the SFF
            # since this is a chicken and egg problem between SFF, and SF creation
            # we give a dummy value then figure out later
            dp_loc_dict['service-function-forwarder'] = 'dummy'
            dp_loc_dict['service-function-ovs:ovs-port'] = {'port-id': ''}
            sf_json['nsh-aware'] = 'true'
            sf_json['ip-mgmt-address'] = vnf_dict[sf]['ip']
            sf_json['type'] = vnf_dict[sf]['type']
            sf_json[dp_loc].append(dp_loc_dict)

            # concat service function json into full dict
            sfs_json = dict(sfs_json.items() + {sf_id: sf_json}.items())

            # map sf id to network id (neutron port)
            sf_net_map[sf] = vnf_dict[sf]['neutron_port_id']

        LOG.debug(_('dictionary for sf_net_map:%s'), sf_net_map)
        LOG.debug(_('dictionary for sf json:%s'), sfs_json)

        # Locate OVS, ovs_mapping will be a nested dict
        # first key is bridge name, secondary keys sfs list, ovs_ip, sff_name
        ovs_mapping = self.locate_ovs_to_sf(sf_net_map)

        LOG.debug(_('OVS MAP:%s'), ovs_mapping)

        # Go back and update sf SFF, tap port
        for br_name in ovs_mapping.keys():
            for sf_id in ovs_mapping[br_name]['sfs']:
                sfs_json[sf_id]['sf-data-plane-locator'][0]['service-function-forwarder'] = ovs_mapping[br_name]['sff_name']
                sfs_json[sf_id][dp_loc][0]['service-function-ovs:ovs-port']['port-id'] = ovs_mapping[br_name][sf_id]['tap_port']
                LOG.debug(_('SF updated with SFF:%s'), ovs_mapping[br_name]['sff_name'])
        # try to create SFs
        for (x, y) in sfs_json.items():
            service_function_json = {'service-function': list()}
            service_function_json['service-function'].append(y)
            LOG.debug(_('json request formatted sf json:%s'), json.dumps(service_function_json))
            sf_result = self.create_odl_sfs(sfs_json=service_function_json)
            if sf_result.status_code != 200:
                LOG.exception(_('Unable to create ODL SF %s'), service_function_json)
                raise ODLSFCreateFailed

        # build SFF dict
        # first we need to see if SFF already exists
        # if so we update with new SFs only
        prev_sff_dict = self.find_existing_sffs(ovs_mapping)
        if prev_sff_dict is not None:
            LOG.debug(_('Previous SFF detected'))
            sff_list = self.create_sff_json(ovs_mapping, sfs_json, prev_sff_dict)
        else:
            sff_list = self.create_sff_json(ovs_mapping, sfs_json)
        # try to create SFFs
        for sff in sff_list:
            sff_json = {'service-function-forwarder': list()}
            sff_json['service-function-forwarder'].append(sff)
            LOG.debug(_('json request formatted sff json:%s'), json.dumps(sff_json))
            sff_result = self.create_odl_sff(sff_json=sff_json)

            if sff_result.status_code != 200:
                LOG.exception(_('Unable to create SFFs'))
                raise ODLSFFCreateFailed

        # try to create SFC
        sfc_json = self.create_sfc_json(sfc_dict, vnf_dict)
        sfc_result = self.create_odl_sfc(sfc_json=sfc_json)

        if sfc_result.status_code != 200:
            LOG.exception(_('Unable to create ODL SFC'))
            raise ODLSFCCreateFailed

        LOG.debug(_('ODL SFC create output:%s'), sfc_result.text)

        # try to create SFP
        sfp_json = self.create_sfp_json(sfc_dict)
        sfp_result = self.create_odl_sfp(sfp_json=sfp_json)

        if sfp_result.status_code != 200:
            LOG.exception(_('Unable to create ODL SFP'))
            raise ODLSFPCreateFailed

        LOG.debug(_('ODL SFP create output:%s'), sfp_result.text)

        # try to create RSP
        rsp_json = self.create_rsp_json(sfp_json)
        rsp_result = self.create_odl_rsp(rsp_json=rsp_json)

        if rsp_result.status_code != 200:
            LOG.exception(_('Unable to create ODL RSP'))
            raise ODLRSPCreateFailed

        LOG.debug(_('ODL RSP create output:%s'), rsp_result.text)

        instance_id = rsp_result.json()['output']['name']

        return instance_id

    @staticmethod
    def create_rsp_json(sfp_dict):
        if isinstance(sfp_dict, dict):
            sfp_name = sfp_dict['service-function-path'][0]['name']
            is_symmetric = sfp_dict['service-function-path'][0]['symmetric']
            rsp_dict = {'input':
                        {'parent-service-function-path': str(sfp_name),
                         'symmetric': str(is_symmetric).lower()}
                        }
        else:
            rsp_dict = {'input': {'parent-service-function-path': str(sfp_dict)}}

        return rsp_dict

    @staticmethod
    def create_sfp_json(sfc_dict):
        sfp_dict = {'service-function-path': list()}
        sfp_def = {'name': "Path-%s" % (sfc_dict['name']),
                   'service-chain-name': sfc_dict['name'],
                   'symmetric': sfc_dict['symmetrical']}
        sfp_dict['service-function-path'].append(sfp_def)

        return sfp_dict

    @staticmethod
    def create_sfc_json(sfc_dict, vnf_dict):
        sfc_json_template = {'name': '',
                             'symmetric': '',
                             'sfc-service-function': '',
                             }
        sf_def_json_template = {'name': '',
                                'type': ''
                                }
        sfc_json = {'service-function-chain': list()}
        temp_sfc_json = sfc_json_template.copy()
        temp_sfc_json['sfc-service-function'] = list()
        for sf in sfc_dict['chain']:
            temp_sf_def_json = sf_def_json_template.copy()
            temp_sf_def_json['name'] = vnf_dict[sf]['name']
            temp_sf_def_json['type'] = vnf_dict[sf]['type']
            temp_sfc_json['sfc-service-function'].append(temp_sf_def_json)

        temp_sfc_json['name'] = sfc_dict['name']
        temp_sfc_json['symmetric'] = str(sfc_dict['symmetrical']).lower()
        sfc_json['service-function-chain'].append(temp_sfc_json)
        LOG.debug(_('dictionary for SFC json:%s'), sfc_json)
        return sfc_json

    def locate_ovs_to_sf(self, sfs_dict):
        """
        :param sfs_dict: dictionary of SFs by id to network id (neutron port id)
        :param driver_name: name of SDN driver
        :return: dictionary mapping sfs to bridge name
        """
        # get topology
        net_response = self.list_network_topology()

        if net_response.status_code != 200:
            LOG.exception(_('Unable to get network topology'))
            raise ODLShowNetworkFailed

        network = net_response.json()

        if network is None:
            return

        LOG.debug(_('Network is %s'), network)

        # br_mapping key is nested dict with br_name as first key
        br_mapping = dict()

        network_map = network['network-topology']['topology']
        # look to see if vm_id exists in network dict
        # FIXME there is a bug here with multiple OVS instances + same bridge name
        for sf in sfs_dict:
            br_dict = self.find_ovs_br(sfs_dict[sf], network_map)
            LOG.debug(_('br_dict from find_ovs %s'), br_dict)
            if br_dict is not None:
                br_id = br_dict['node-id']
                br_name = br_dict['br_name']
                if br_id in br_mapping:
                    br_mapping[br_id]['sfs'] = [sf]+br_mapping[br_id]['sfs']
                    br_mapping[br_id][sf] = dict()
                    br_mapping[br_id][sf]['tap_port'] = br_dict['tap_port']
                else:
                    br_mapping[br_id] = dict()
                    br_mapping[br_id]['br_name'] = br_name
                    br_mapping[br_id]['sfs'] = [sf]
                    br_mapping[br_id]['ovs_ip'] = br_dict['ovs_ip']
                    br_mapping[br_id][sf] = dict()
                    br_mapping[br_id][sf]['tap_port'] = br_dict['tap_port']
                    prev_sff_dict = self.find_existing_sffs(br_mapping)

                    if prev_sff_dict is not None and br_id in prev_sff_dict:
                        br_mapping[br_id]['sff_name'] = prev_sff_dict[br_id]['name']
                    else:
                        # Must be a new SFF
                        br_mapping[br_id]['sff_name'] = 'sff' + str(self.sff_counter)
                        self.sff_counter += 1
            else:
                LOG.debug(_('Could not find OVS bridge for %s'), sf)

        return br_mapping

    def find_existing_sffs(self, bridge_mapping):
        """
        Checks for previous SFF configured for this OVS
        :param bridge_mapping: OVS dictionary to check if SFF exists
        :return: dictionary of SFF or None
        """

        sff_response = self.get_odl_sff()
        if sff_response.status_code != 200:
            LOG.warn(_('Unable to get SFFs from ODL'))
            return

        try:
            odl_sff_list = sff_response.json()['service-function-forwarders']['service-function-forwarder']
        except KeyError:
            return
        sff_br_dict = dict()
        for br in bridge_mapping.keys():
            for sff in odl_sff_list:
                if sff['ip-mgmt-address'] == bridge_mapping[br]['ovs_ip']:
                    # for now we assume that SFF would only be br-int
                    # thus there cannot be another ovs bridge name
                    # so we don't check, may change this in future
                    sff_br_dict[br] = sff
                    continue

        if sff_br_dict:
            return sff_br_dict

    @staticmethod
    def create_sff_json(bridge_mapping, sfs_dict, prev_sff_dict=None):
        """
        Creates JSON request body for ODL SFC
        :param bridge_mapping: dictionary of sf to ovs bridges
        :param sfs_dict: dictionary of all SFs on the bridge
        :param prev_sff_dict: if exists, update previous SFF
        :return: dictionary with formatted fields
        """
        dp_loc = 'sf-data-plane-locator'
        sff_opts = {"remote-ip": "flow",
                    "dst-port": "6633",
                    "key": "flow",
                    "nsp": "flow",
                    "nsi": "flow",
                    "nshc1": "flow",
                    "nshc2": "flow",
                    "nshc3": "flow",
                    "nshc4": "flow"}
        sff_dp_loc = {'name': '',
                      'data-plane-locator':
                          {
                          'transport': 'service-locator:vxlan-gpe',
                          'port': '',
                          'ip': ''
                          },
                      'service-function-forwarder-ovs:ovs-options': sff_opts
                      }
        sf_template = {'name': ''}
                       #'type': ''
                       #}
#        sff_sf_dp_loc = {'service-function-forwarder-ovs:ovs-bridge': '',
#                         'transport': 'service-locator:vxlan-gpe',
#                         'port': '',
#                         'ip': ''
#                         }

        sff_sf_dp_loc = {'sff-dpl-name': '',
                         'sf-dpl-name': ''
                         }

        sff_list = []
        # build dict for each bridge
        for br in bridge_mapping.keys():
            # create sff data-plane locator
            temp_sff_dp_loc = sff_dp_loc.copy()
            temp_sff_dp_loc['name'] = 'vxgpe'
            temp_sff_dp_loc['data-plane-locator']['port'] = '6633'
            temp_sff_dp_loc['data-plane-locator']['ip'] = bridge_mapping[br]['ovs_ip']
            # temp_sff_dp_loc['service-function-forwarder-ovs:ovs-bridge'] = br
            temp_bridge_dict = {'bridge-name': bridge_mapping[br]['br_name']}
            sf_dicts = list()
            for sf in bridge_mapping[br]['sfs']:
                # build sf portion of dict
                temp_sf_dict = sf_template.copy()
                temp_sf_dict['name'] = sfs_dict[sf]['name']
                #temp_sf_dict['type'] = sfs_dict[sf]['type']
                # build sf data-plane locator
                temp_sff_sf_dp_loc = sff_sf_dp_loc.copy()
                temp_sff_sf_dp_loc['sff-dpl-name'] = 'vxgpe'
                # trozet hardcoding first data-plane-locator index
                temp_sff_sf_dp_loc['sf-dpl-name'] = sfs_dict[sf][dp_loc][0]['name']

                temp_sf_dict['sff-sf-data-plane-locator'] = temp_sff_sf_dp_loc
                sf_dicts.append(temp_sf_dict)

            # if exists, use current sff, and only update sfs
            if prev_sff_dict and br in prev_sff_dict.keys():
                temp_sff = prev_sff_dict[br]
                prev_sff_sf_list = temp_sff['service-function-dictionary']

                for new_sf in sf_dicts:
                    new_sf_updated = False
                    for index, sf in enumerate(prev_sff_sf_list):
                        if sf['name'] == new_sf['name']:
                            # update/replace old sf, if they were same name
                            temp_sff['service-function-dictionary'][index] = new_sf
                            new_sf_updated = True
                            break

                    if not new_sf_updated:
                        temp_sff['service-function-dictionary'].append(new_sf)

            else:
                # combine sf list into sff dict
                temp_sff = dict({'name': bridge_mapping[br]['sff_name']}.items()
                                + {'sff-data-plane-locator': [temp_sff_dp_loc]}.items()
                                + {'service-function-dictionary': sf_dicts}.items())
                temp_sff['ip-mgmt-address'] = bridge_mapping[br]['ovs_ip']
                temp_sff['service-node'] = ''
                temp_sff['service-function-forwarder-ovs:ovs-bridge'] = temp_bridge_dict

            sff_list.append(copy.deepcopy(temp_sff))

        LOG.debug(_('SFF list output is %s'), sff_list)
        return sff_list

    @staticmethod
    def find_ovs_br(sf_id, network_map):
        """
        :param sf_id: info to ID an sf, for example neutron port id
        :param network_map: ovsdb network topology list
        :return: bridge_dict: br_name, ovs_ip, ovs_port key-values
        """
        # trozet better way to traverse this is to use json lib itself
        # for now this was quicker to write
        bridge_dict = dict()
        for net in network_map:
            if 'node' in net:
                for node_entry in net['node']:
                    if 'termination-point' in node_entry:
                        for endpoint in node_entry['termination-point']:
                            if bridge_dict:
                                break
                            elif 'ovsdb:interface-external-ids' in endpoint:
                                for external_id in endpoint['ovsdb:interface-external-ids']:
                                    if 'external-id-value' in external_id:
                                        if external_id['external-id-value'] == sf_id:
                                            print 'Found!'
                                            print node_entry['ovsdb:bridge-name']
                                            bridge_dict['node-id'] = node_entry['node-id']
                                            bridge_dict['br_name'] = node_entry['ovsdb:bridge-name']
                                            full_node_id = node_entry['node-id']
                                            node_id = re.sub('/bridge.*$', '', full_node_id)
                                            bridge_dict['tap_port'] = endpoint['ovsdb:name']
                                            break
                                        else:
                                            print 'Not Found'
                if 'br_name' in bridge_dict:
                    for node_entry in net['node']:
                        if node_entry['node-id'] == node_id and 'ovsdb:connection-info' in node_entry:
                            bridge_dict['ovs_ip'] = node_entry['ovsdb:connection-info']['remote-ip']
                            bridge_dict['ovs_port'] = node_entry['ovsdb:connection-info']['remote-port']
                            break
        if all(key in bridge_dict for key in ('br_name', 'ovs_ip', 'ovs_port', 'tap_port')):
            return bridge_dict

        return

    # TODO implement this
    def create_wait(self, sfc_dict, sfc_id):
        pass

    @log.log
    def delete_sfc(self, instance_id, is_symmetrical):
        instance_list = [instance_id]
        if is_symmetrical:
            reverse_id = "%s-Reverse" % str(instance_id)
            instance_list.append(reverse_id)
        for instance in instance_list:
            rsp_dict = {'input': {'name': str(instance)}}
            rsp_result = self.delete_odl_rsp(rsp_dict)

            if rsp_result.status_code != 200:
                LOG.exception(_('Unable to delete RSP'))
                raise ODLRSPDeleteFailed

        return

    @log.log
    def update_sfc(self, instance_id, update_sfc_dict, vnf_dict):
        raise NotImplementedError
