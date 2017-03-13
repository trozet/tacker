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


import copy
import eventlet
import inspect

from oslo_config import cfg
from sqlalchemy.orm import exc as orm_exc

from tacker.api.v1 import attributes
from tacker.common import driver_manager
from tacker.common import utils as common_utils
from tacker import context as t_context
from tacker.db.sfc import sfc_db
from tacker.extensions import sfc
from tacker.openstack.common import excutils
from tacker.openstack.common import log as logging
from tacker.plugins.common import constants
from keystoneauth1.identity import v3
from keystoneauth1 import session
from neutronclient.v2_0 import client as neutron_client
from tacker.db.vm.vm_db import VNFMPluginDb
from tacker import manager
import json
import re

LOG = logging.getLogger(__name__)


class SFCPlugin(sfc_db.SFCPluginDb):
    """SFCPlugin which supports SFC framework
    """
    OPTS = [
        cfg.ListOpt(
            'infra_driver', default=['opendaylight'],
            help=_('Hosting device drivers sfc plugin will use')),
    ]
    cfg.CONF.register_opts(OPTS, 'sfc')
    supported_extension_aliases = ['sfc']

    def __init__(self):
        super(SFCPlugin, self).__init__()
        self._pool = eventlet.GreenPool()
        self._device_manager = driver_manager.DriverManager(
            'tacker.sfc.drivers',
            cfg.CONF.sfc.infra_driver)

    def spawn_n(self, function, *args, **kwargs):
        self._pool.spawn_n(function, *args, **kwargs)

    def _find_vnf_info(self, context, chain):
        sfc_dict = dict()
        for vnf in chain:
            vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
            vnf_data = vnfm_plugin.get_vnf(context, vnf)
            sfc_dict[vnf] = dict()
            # find IP in mgmt_url string
            sfc_dict[vnf]['ip'] = re.search(r'[0-9]+(?:\.[0-9]+){3}', vnf_data['mgmt_url']).group()
            # trozet check here to see how services are passed
            # we can only specify 1 atm for ODL
            sfc_dict[vnf]['type'] = vnf_data['attributes']['service_type']
            sfc_dict[vnf]['name'] = vnf_data['name']
            # we also need the neutron port ID
            # tacker doesnt find this so we can use the vnf id to find the
            # neutron port as it is listed in the name
            nc = NeutronClient()
            port_output = nc.list_neutron_ports()
            for port in port_output['ports']:
                if port['name'].find(vnf_data['id']) > 0:
                    sfc_dict[vnf]['neutron_port_id'] = port['id']
            if 'neutron_port_id' not in sfc_dict[vnf]:
                raise KeyError('Unable to find neutron_port_id')

        return sfc_dict

    def _create_sfc(self, context, sfcd):
        """
        :param context:
        :param sfcd: dictionary of kwargs from REST request
        :return: dictionary of created object?
        """
        sfc_dict = sfcd['sfc']
        LOG.debug(_('chain_dict %s'), sfc_dict)
        vnf_dict = self._find_vnf_info(context, sfc_dict['chain'])
        LOG.debug(_('VNF DICT: %s'), vnf_dict)
        sfc_dict = self._create_sfc_pre(context, sfcd)
        LOG.debug(_('sfc_dict after database entry %s'), sfc_dict)

        sfc_id = sfc_dict['id']
        # Default driver for SFC is opendaylight
        # when other drivers are available switch on them here
        if 'infra_driver' not in sfc_dict:
            infra_driver = 'opendaylight'
        else:
            infra_driver = sfc_dict['infra_driver']

        instance_id = self._device_manager.invoke(infra_driver, 'create_sfc', sfc_dict=sfc_dict, vnf_dict=vnf_dict)

        if instance_id is None:
            self._create_sfc_post(context, sfc_id, None, sfc_dict)
            self._create_sfc_status(context, sfc_id, constants.ERROR)
            return sfc_dict

        sfc_dict['instance_id'] = instance_id
        LOG.debug(_('sfc_dict after sfc SFC Create complete: %s'), sfc_dict)
        self._create_sfc_post(context, sfc_id, instance_id, sfc_dict)
        new_status = constants.ACTIVE
        self._create_sfc_status(context, sfc_id, new_status)

        return sfc_dict

    def create_sfc(self, context, sfc):
        self.sfc_exists(context, sfc['sfc']['name'])
        sfc_dict = self._create_sfc(context, sfc)
        # TODO fix this or remove it, not sure if ODL is synchronous here
        #def create_sfc_wait():
        #    self._create_sfc_wait(context, sfc_dict)

        #self.spawn_n(create_sfc_wait)
        return sfc_dict

    def _create_sfc_wait(self, context, sfc_dict):
        driver_name = self._infra_driver_name(sfc_dict)
        sfc_id = sfc_dict['id']
        instance_id = self._instance_id(sfc_dict)

        try:
            self._device_manager.invoke(
                driver_name, 'create_wait',
                sfc_dict=sfc_dict, sfc_id=instance_id)
        except sfc.SFCCreateWaitFailed:
            instance_id = None
            del sfc_dict['instance_id']

        self._create_sfc_post(
            context, sfc_id, instance_id, sfc_dict)
        if instance_id is None:
            return

        new_status = constants.ACTIVE

        sfc_dict['status'] = new_status
        self._create_sfc_status(context, sfc_id, new_status)

    def delete_sfc(self, context, sfc_id):
        sfc_dict = self._delete_sfc_pre(context, sfc_id)
        driver_name = self._infra_driver_name(sfc_dict)
        instance_id = self._instance_id(sfc_dict)
        symmetrical = sfc_dict['symmetrical']

        try:
            self._device_manager.invoke(driver_name, 'delete_sfc',
                                        instance_id=instance_id,
                                        is_symmetrical=symmetrical)
        except Exception as e:
            with excutils.save_and_reraise_exception():
                self._delete_sfc_post(context, sfc_id, e)

        self._delete_sfc_post(context, sfc_id, None)

    def update_sfc(self, context, sfc_id, sfc):
        sfc_dict = self._update_sfc_pre(context, sfc_id)
        driver_name = self._infra_driver_name(sfc_dict)
        instance_id = self._instance_id(sfc_dict)
        update_dict = sfc['sfc']
        vnf_dict = self._find_vnf_info(context, update_dict['chain'])
        try:
            self._device_manager.invoke(
                driver_name, 'update', plugin=self, update_sfc_dict=update_dict,
                vnf_dict=vnf_dict, instance_id=instance_id)
        except Exception:
            with excutils.save_and_reraise_exception():
                self._update_sfc_post(context, sfc_id, constants.ERROR)

        # TODO implement update wait and check updated
        new_status = constants.ACTIVE
        self._update_device_post(context, sfc_dict['id'],
                                 new_status, update_dict)
        return update_dict


class NeutronClient:
    def __init__(self):
        auth_url = common_utils.format_auth_uri_version(
            cfg.CONF.keystone_authtoken.auth_uri)
        authtoken = cfg.CONF.keystone_authtoken
        if common_utils.is_auth_uri_v3(auth_url):
            auth = v3.Password(auth_url=auth_url,
                               username=authtoken.username,
                               password=authtoken.password,
                               project_name=authtoken.project_name,
                               user_domain_id=authtoken.user_domain_id,
                               project_domain_id=authtoken.project_domain_id)
            sess = session.Session(auth=auth)
            self.client = neutron_client.Client(session=sess)
        else:
            kwargs = {
                'password': authtoken.password,
                'tenant_name': authtoken.project_name,
                'username': authtoken.username,
                'auth_url': auth_url,
            }
            self.client = neutron_client.Client(**kwargs)

    def list_neutron_ports(self):
        LOG.debug("list_ports()", )
        port_info = self.client.list_ports()
        print "API.Tacker Neutron Port List::" + str(port_info)
        return port_info
