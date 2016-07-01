# Copyright 2016 Red Hat Inc
# All Rights Reserved.
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

import json
import random
import sqlalchemy as sa
import uuid
import yaml

from oslo_log import log as logging
from oslo_utils import uuidutils
from sqlalchemy import orm
from sqlalchemy.orm import exc as orm_exc
from sqlalchemy.types import PickleType
from tacker.db import db_base
from tacker.db import model_base
from tacker.db import models_v1
from tacker.db import types
from tacker.extensions.nfvo import ClassifierInUse
from tacker.extensions.nfvo import ClassifierNotFound
from tacker.extensions.nfvo import NfpAttributeNotFound
from tacker.extensions.nfvo import NfpForwarderNotFound
from tacker.extensions.nfvo import NfpInUse
from tacker.extensions.nfvo import NfpNotFound
from tacker.extensions.nfvo import NfpPolicyCriteriaError
from tacker.extensions.nfvo import NfpPolicyNotFound
from tacker.extensions.nfvo import NfpPolicyTypeError
from tacker.extensions.nfvo import NfpRequirementsException
from tacker.extensions.nfvo import SfcInUse
from tacker.extensions.nfvo import SfcNotFound
from tacker.extensions.nfvo import VnffgCpNotFoundException
from tacker.extensions.nfvo import VnffgdInUse
from tacker.extensions.nfvo import VnffgdNotFound
from tacker.extensions.nfvo import VnffgdVnfdNotFoundException
from tacker.extensions.nfvo import VnffgdVnfNotFoundException
from tacker.extensions.nfvo import VnffgInUse
from tacker.extensions.nfvo import VnffgInvalidMappingException
from tacker.extensions.nfvo import VnffgNotFound
from tacker.extensions.nfvo import VnffgPropertyNotFound
from tacker import manager
from tacker.plugins.common import constants


LOG = logging.getLogger(__name__)
_ACTIVE_UPDATE = (constants.ACTIVE, constants.PENDING_UPDATE)
_ACTIVE_UPDATE_ERROR_DEAD = (
    constants.PENDING_CREATE, constants.ACTIVE, constants.PENDING_UPDATE,
    constants.ERROR, constants.DEAD)
MATCH_CRITERIA = (
    'eth_type', 'eth_src', 'eth_dst', 'vlan_id', 'vlan_pcp', 'mpls_label',
    'mpls_tc', 'ip_dscp', 'ip_ecn', 'ip_src_prefix', 'ip_dst_prefix',
    'ip_proto', 'destination_port_range', 'source_port_range',
    'network_src_port_id', 'network_dst_port_id', 'network_id', 'network_name',
    'tenant_id', 'icmpv4_type', 'icmpv4_code', 'arp_op', 'arp_spa',
    'arp_tpa', 'arp_sha', 'arp_tha', 'ipv6_src', 'ipv6_dst', 'ipv6_flabel',
    'icmpv6_type', 'icmpv6_code', 'ipv6_nd_target', 'ipv6_nd_sll',
    'ipv6_nd_tll')

MATCH_DB_KEY_LIST = (
    'eth_type', 'eth_src', 'eth_dst', 'vlan_id', 'vlan_pcp', 'mpls_label',
    'mpls_tc', 'ip_dscp', 'ip_ecn', 'ip_src_prefix', 'ip_dst_prefix',
    'ip_proto', 'destination_port_min', 'destination_port_max',
    'source_port_min', 'source_port_max', 'network_src_port_id',
    'network_dst_port_id', 'network_id', 'tenant_id', 'icmpv4_type',
    'icmpv4_code', 'arp_op', 'arp_spa', 'arp_tpa', 'arp_sha', 'arp_tha',
    'ipv6_src', 'ipv6_dst', 'ipv6_flabel', 'icmpv6_type', 'icmpv6_code',
    'ipv6_nd_target', 'ipv6_nd_sll', 'ipv6_nd_tll'
)

CP = 'connection_points'


class VnffgTemplate(model_base.BASE, models_v1.HasId, models_v1.HasTenant):
    """Represents template to create a VNF Forwarding Graph."""

    # Descriptive name
    name = sa.Column(sa.String(255), nullable=False)
    description = sa.Column(sa.Text)

    # Vnffg template
    template = sa.Column(PickleType(pickler=json))


class Vnffg(model_base.BASE, models_v1.HasTenant, models_v1.HasId):
    """VNF Forwarding Graph Data Model"""

    name = sa.Column(sa.String(255), nullable=True)
    description = sa.Column(sa.String(255), nullable=True)

    # List of associated NFPs
    forwarding_paths = orm.relationship("VnffgNfp", backref="vnffg")

    vnffgd_id = sa.Column(types.Uuid, sa.ForeignKey('vnffgtemplates.id'))
    vnffgd = orm.relationship('VnffgTemplate')

    status = sa.Column(sa.String(255), nullable=False)

    # Mapping of VNFD to VNF instance names
    vnf_mapping = sa.Column(PickleType(pickler=json))


class VnffgNfp(model_base.BASE, models_v1.HasTenant, models_v1.HasId):
    """Network Forwarding Path Data Model"""

    name = sa.Column(sa.String(255), nullable=True)
    vnffg_id = sa.Column(types.Uuid, sa.ForeignKey('vnffgs.id'),
                         nullable=False)
    classifier_id = sa.Column(types.Uuid, sa.ForeignKey('vnffgclassifiers.id'))
    classifier = orm.relationship('VnffgClassifier', backref='nfp',
                                  uselist=False, foreign_keys=[classifier_id])
    chain_id = sa.Column(types.Uuid, sa.ForeignKey('vnffgchains.id'))
    chain = orm.relationship('VnffgChain', backref='nfp',
                             uselist=False, foreign_keys=[chain_id])

    status = sa.Column(sa.String(255), nullable=False)
    path_id = sa.Column(sa.String(255), nullable=False)

    # symmetry of forwarding path
    symmetrical = sa.Column(sa.Boolean(), default=False)


class VnffgChain(model_base.BASE, models_v1.HasTenant, models_v1.HasId):
    """Service Function Chain Data Model"""

    status = sa.Column(sa.String(255), nullable=False)

    instance_id = sa.Column(sa.String(255), nullable=True)

    # symmetry of forwarding path
    symmetrical = sa.Column(sa.Boolean(), default=False)

    # chain
    chain = sa.Column(PickleType(pickler=json))

    path_id = sa.Column(sa.String(255), nullable=False)
    nfp_id = sa.Column(types.Uuid, nullable=True)

    __table_args__ = (sa.ForeignKeyConstraint(['nfp_id'], ['vnffgnfps.id'],
                                              name='fk_chain_vnffgnfp',
                                              use_alter=True),
                      {'mysql_engine': 'InnoDB'})


class VnffgClassifier(model_base.BASE, models_v1.HasTenant, models_v1.HasId):
    """VNFFG NFP Classifier Data Model"""

    status = sa.Column(sa.String(255), nullable=False)

    instance_id = sa.Column(sa.String(255), nullable=True)

    chain_id = sa.Column(types.Uuid, sa.ForeignKey('vnffgchains.id'))
    chain = orm.relationship('VnffgChain', backref='classifier',
                             uselist=False, foreign_keys=[chain_id])
    nfp_id = sa.Column(types.Uuid, nullable=True)
    # match criteria
    match = orm.relationship('ACLMatchCriteria')

    __table_args__ = (sa.ForeignKeyConstraint(['nfp_id'],
                                              ['vnffgnfps.id'],
                                              name='fk_classifier_vnffgnfp',
                                              use_alter=True),
                      {'mysql_engine': 'InnoDB'})


class ACLMatchCriteria(model_base.BASE, models_v1.HasId):
    """Represents ACL match criteria of a classifier."""

    vnffgc_id = sa.Column(types.Uuid, sa.ForeignKey('vnffgclassifiers.id'))
    eth_src = sa.Column(sa.String(36), nullable=True)
    eth_dst = sa.Column(sa.String(36), nullable=True)
    eth_type = sa.Column(sa.String(36), nullable=True)
    vlan_id = sa.Column(sa.Integer, nullable=True)
    vlan_pcp = sa.Column(sa.Integer, nullable=True)
    mpls_label = sa.Column(sa.Integer, nullable=True)
    mpls_tc = sa.Column(sa.Integer, nullable=True)
    ip_dscp = sa.Column(sa.Integer, nullable=True)
    ip_ecn = sa.Column(sa.Integer, nullable=True)
    ip_src_prefix = sa.Column(sa.String(36), nullable=True)
    ip_dst_prefix = sa.Column(sa.String(36), nullable=True)
    source_port_min = sa.Column(sa.Integer, nullable=True)
    source_port_max = sa.Column(sa.Integer, nullable=True)
    destination_port_min = sa.Column(sa.Integer, nullable=True)
    destination_port_max = sa.Column(sa.Integer, nullable=True)
    ip_proto = sa.Column(sa.Integer, nullable=True)
    network_id = sa.Column(types.Uuid, nullable=True)
    network_src_port_id = sa.Column(types.Uuid, nullable=True)
    network_dst_port_id = sa.Column(types.Uuid, nullable=True)
    tenant_id = sa.Column(sa.String(64), nullable=True)
    icmpv4_type = sa.Column(sa.Integer, nullable=True)
    icmpv4_code = sa.Column(sa.Integer, nullable=True)
    arp_op = sa.Column(sa.Integer, nullable=True)
    arp_spa = sa.Column(sa.String(36), nullable=True)
    arp_tpa = sa.Column(sa.String(36), nullable=True)
    arp_sha = sa.Column(sa.String(36), nullable=True)
    arp_tha = sa.Column(sa.String(36), nullable=True)
    ipv6_src = sa.Column(sa.String(36), nullable=True)
    ipv6_dst = sa.Column(sa.String(36), nullable=True)
    ipv6_flabel = sa.Column(sa.Integer, nullable=True)
    icmpv6_type = sa.Column(sa.Integer, nullable=True)
    icmpv6_code = sa.Column(sa.Integer, nullable=True)
    ipv6_nd_target = sa.Column(sa.String(36), nullable=True)
    ipv6_nd_sll = sa.Column(sa.String(36), nullable=True)
    ipv6_nd_tll = sa.Column(sa.String(36), nullable=True)


class VnffgDbMixin(db_base.CommonDbMixin):

    def __init__(self):
        super(VnffgDbMixin, self).__init__()

    def create_vnffg(self, context, vnffg):
        vnffg_dict = self._create_vnffg_pre(context, vnffg)
        sfc_instance = str(uuid.uuid4())
        fc_instance = str(uuid.uuid4())
        self._create_vnffg_post(context, sfc_instance,
                                fc_instance, vnffg_dict)
        self._create_vnffg_status(context, vnffg_dict)
        return vnffg_dict

    def get_vnffg(self, context, vnffg_id, fields=None):
        vnffg_db = self._get_resource(context, Vnffg, vnffg_id)
        return self._make_vnffg_dict(vnffg_db, fields)

    def get_vnffgs(self, context, filters=None, fields=None):
        vnffgs = self._get_collection(context, Vnffg, self._make_vnffg_dict,
                                      filters=filters, fields=fields)
        # Ugly hack to mask internally used record
        return [vnffg for vnffg in vnffgs
                if uuidutils.is_uuid_like(vnffg['id'])]

    def update_vnffg(self, context, vnffg_id, vnffg):
        vnffg_dict = self._update_vnffg_pre(context, vnffg_id)
        # start actual update of hosting device
        # waiting for completion of update should be done in background
        # by another thread if it takes a while
        self._update_vnffg_post(context, vnffg_id, constants.ACTIVE)
        return vnffg_dict

    def delete_vnffg(self, context, vnffg_id):
        self._delete_vnffg_pre(context, vnffg_id)
        # start actual deletion of hosting device.
        # Waiting for completion of deletion should be done in background
        # by another thread if it takes a while.
        self._delete_vnffg_post(context, vnffg_id, False)

    def create_vnffgd(self, context, vnffgd):
        template = vnffgd['vnffgd']
        LOG.debug(_('template %s'), template)
        tenant_id = self._get_tenant_id_for_create(context, template)

        with context.session.begin(subtransactions=True):
            template_id = str(uuid.uuid4())
            template_db = VnffgTemplate(
                id=template_id,
                tenant_id=tenant_id,
                name=template.get('name'),
                description=template.get('description'),
                template=template.get('attributes'))
            context.session.add(template_db)

        LOG.debug(_('template_db %(template_db)s'),
                  {'template_db': template_db})
        return self._make_template_dict(template_db)

    def get_vnffgd(self, context, vnffgd_id, fields=None):
        template_db = self._get_resource(context, VnffgTemplate,
                                         vnffgd_id)
        return self._make_template_dict(template_db, fields)

    def get_vnffgds(self, context, filters=None, fields=None):
        return self._get_collection(context, VnffgTemplate,
                                    self._make_template_dict,
                                    filters=filters, fields=fields)

    def delete_vnffgd(self, context, vnffgd_id):
        with context.session.begin(subtransactions=True):
            # TODO(yamahata): race. prevent from newly inserting hosting device
            #                 that refers to this template
            vnffg_db = context.session.query(Vnffg).filter_by(
                vnffgd_id=vnffgd_id).first()
            if vnffg_db is not None:
                raise VnffgdInUse(vnffgd_id=vnffgd_id)

            template_db = self._get_resource(context, VnffgTemplate,
                                             vnffgd_id)
            context.session.delete(template_db)

    def get_classifier(self, context, classifier_id, fields=None):
        classifier_db = self._get_resource(context, VnffgClassifier,
                                           classifier_id)
        return self._make_classifier_dict(classifier_db, fields)

    def get_classifiers(self, context, filters=None, fields=None):
        classifiers = self._get_collection(context, VnffgClassifier,
                                           self._make_classifier_dict,
                                           filters=filters, fields=fields)
        # Ugly hack to mask internally used record
        return [classifier for classifier in classifiers
                if uuidutils.is_uuid_like(classifier['id'])]

    def get_nfp(self, context, nfp_id, fields=None):
        nfp_db = self._get_resource(context, VnffgNfp, nfp_id)
        return self._make_nfp_dict(nfp_db, fields)

    def get_nfps(self, context, filters=None, fields=None):
        nfps = self._get_collection(context, VnffgNfp,
                                    self._make_nfp_dict,
                                    filters=filters, fields=fields)
        # Ugly hack to mask internally used record
        return [nfp for nfp in nfps
                if uuidutils.is_uuid_like(nfp['id'])]

    def get_sfc(self, context, sfc_id, fields=None):
        chain_db = self._get_resource(context, VnffgChain, sfc_id)
        return self._make_chain_dict(chain_db, fields)

    def get_sfcs(self, context, filters=None, fields=None):
        chains = self._get_collection(context, VnffgChain,
                                      self._make_chain_dict,
                                      filters=filters, fields=fields)
        # Ugly hack to mask internally used record
        return [chain for chain in chains
                if uuidutils.is_uuid_like(chain['id'])]

    # called internally, not by REST API
    def _create_vnffg_pre(self, context, vnffg):
        vnffg = vnffg['vnffg']
        LOG.debug(_('vnffg %s'), vnffg)
        tenant_id = self._get_tenant_id_for_create(context, vnffg)
        name = vnffg.get('name')
        vnffg_id = vnffg.get('id') or str(uuid.uuid4())
        template_id = vnffg['vnffgd_id']
        symmetrical = vnffg['symmetrical']

        with context.session.begin(subtransactions=True):
            template_db = self._get_resource(context, VnffgTemplate,
                                             template_id)
            LOG.debug(_('vnffg template %s'), template_db)
            vnf_members = self._get_vnffg_property(template_db,
                                                   'constituent_vnfs')
            LOG.debug(_('Constituent VNFs: %s'), vnf_members)
            vnf_mapping = self._get_vnf_mapping(context, vnffg.get(
                                                'vnf_mapping'), vnf_members)
            # create NFP dict
            nfp_dict = self._create_nfp_pre(template_db)
            vnffg_db = Vnffg(id=vnffg_id,
                             tenant_id=tenant_id,
                             name=name,
                             description=template_db.description,
                             vnf_mapping=vnf_mapping,
                             vnffgd_id=template_id,
                             status=constants.PENDING_CREATE)
            context.session.add(vnffg_db)

            nfp_id = str(uuid.uuid4())
            sfc_id = str(uuid.uuid4())
            classifier_id = str(uuid.uuid4())

            nfp_db = VnffgNfp(id=nfp_id, vnffg_id=vnffg_id,
                              tenant_id=tenant_id,
                              name=nfp_dict['name'],
                              status=constants.PENDING_CREATE,
                              path_id=nfp_dict['path_id'],
                              classifier_id=classifier_id,
                              chain_id=sfc_id,
                              symmetrical=symmetrical)
            context.session.add(nfp_db)

            chain = self._create_chain_pre(context, vnf_mapping, template_db,
                                           nfp_dict['name'])
            LOG.debug(_('chain: %s'), chain)
            sfc_db = VnffgChain(id=sfc_id,
                                tenant_id=tenant_id,
                                status=constants.PENDING_CREATE,
                                symmetrical=symmetrical,
                                chain=chain,
                                path_id=nfp_dict['path_id'])

            context.session.add(sfc_db)

            sfcc_db = VnffgClassifier(id=classifier_id,
                                      tenant_id=tenant_id,
                                      status=constants.PENDING_CREATE,
                                      chain_id=sfc_id,
                                      nfp_id=nfp_id)
            context.session.add(sfcc_db)

            match = self._policy_to_acl_criteria(template_db, nfp_dict['name'])
            LOG.debug(_('acl_match %s'), match)

            match_db_table = ACLMatchCriteria(
                id=str(uuid.uuid4()),
                vnffgc_id=classifier_id,
                **match)

            context.session.add(match_db_table)

            # hack to avoid foreign key constraint errors with nfp_id
            query = (self._model_query(context, VnffgChain).
                     filter(VnffgChain.id == sfc_id).
                     filter(VnffgChain.status == constants.PENDING_CREATE).
                     one())
            query.update({'nfp_id': nfp_id})

            query = (self._model_query(context, VnffgClassifier).
                     filter(VnffgClassifier.id == classifier_id).
                     filter(VnffgClassifier.status ==
                            constants.PENDING_CREATE).one())
            query.update({'nfp_id': nfp_id})

        return self._make_vnffg_dict(vnffg_db)

    @staticmethod
    def _create_nfp_pre(template_db):
        template = yaml.load(template_db.template['vnffgd'])
        nfp_dict = dict()
        vnffg_name = template['groups'].keys()[0]
        # we assume only one NFP for initial implementation
        nfp_dict['name'] = template['groups'][vnffg_name]['members'][0]
        nfp_dict['path_id'] = template[nfp_dict['name']]['id']

        if not nfp_dict['path_id']:
            # TODO(trozet): do we need to check if this path ID is already
            # taken by another VNFFG
            nfp_dict['path_id'] = random.randint(1, 16777216)

        return nfp_dict

    def _create_chain_pre(self, context, vnf_mapping, template_db, nfp_name):
        """Creates a list of physical port ids to represent an ordered chain

        :param vnf_mapping: dict of VNFD to VNF instance mappings
        :param template_db: VNFFG Descriptor
        :return: list of port chain including vnf name and list of CPs
        """
        chain_list = []
        prev_forwarder = None
        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        # Build the list of logical chain representation
        logical_chain = self._get_nfp_attribute(template_db, nfp_name)
        # Build physical port chain
        for element in logical_chain:
            if element['forwarder'] not in vnf_mapping.keys():
                raise NfpForwarderNotFound(vnfd=element['forwarder'],
                                           mapping=vnf_mapping)
            # TODO(trozet): validate CP in VNFD has forwarding capability
            # Find VNF
            vnf = vnfm_plugin.get_vnf(context, vnf_mapping[element[
                                      'forwarder']])
            try:
                vnf_cp = vnf['vnf_details'][element['capability']]
            except KeyError:
                raise VnffgCpNotFoundException(cp_id=element['capability'],
                                               vnf_id=vnf['id'])
            # Check if this is a new VNF entry in the chain
            if element['forwarder'] != prev_forwarder:

                chain_list.append({'name': vnf['name'],
                                   CP: [vnf_cp]})
                prev_forwarder = element['forwarder']
            # Must be an egress CP
            else:
                if len(chain_list[-1][CP]) > 1:
                    raise NfpRequirementsException(vnfd=element['forwarder'])
                else:
                    chain_list[-1]['connection_points'].append(vnf_cp)

        return chain_list

    @staticmethod
    def _get_vnffg_property(template_db, vnffg_property):
        template = yaml.load(template_db.template['vnffgd'])
        vnffg_name = template['groups'].keys()[0]
        try:
            return template['groups'][vnffg_name]['properties'][vnffg_property]
        except KeyError:
            raise VnffgPropertyNotFound(vnffg_property=vnffg_property)

    @staticmethod
    def _get_nfp_attribute(template_db, nfp, attribute):
        """Finds any attribute of an NFP described in a template

        :param template_db: VNFFGD template
        :param nfp: name of NFP
        :param attribute: attribute to find
        :return: value of attribute from template
        """
        template = yaml.load(template_db.template['vnffgd'])
        try:
            return template[nfp][attribute]
        except KeyError:
            raise NfpAttributeNotFound(attribute=attribute)

    def _get_vnf_mapping(self, context, vnf_mapping, vnf_members):
        """Creates/validates a mapping of VNFD names to VNF IDs for NFP.

        :param context: SQL session context
        :param vnf_mapping: dict of requested VNFD:VNF_ID mappings
        :param vnf_members: list of constituent VNFs from a VNFFG
        :return: dict of VNFD:VNF_ID mappings
        """
        vnfm_plugin = manager.TackerManager.get_service_plugins()['VNFM']
        new_mapping = dict()

        for vnfd in vnf_members:
            vnfd_id = vnfm_plugin.get_vnfds(context, {'name': vnfd},
                                            fields='template_id')
            if vnfd_id is None:
                raise VnffgdVnfdNotFoundException(vnfd_name=vnfd)
            else:
                # if no VNF mapping, we need to abstractly look for instances
                # that match VNFD
                if vnf_mapping is None or vnfd not in vnf_mapping.keys():
                    # find suitable VNFs from vnfd_id
                    vnf_list = vnfm_plugin.get_vnfs(context,
                                                    {'template_id': vnfd_id},
                                                    fields='id')
                    if vnf_list is None:
                        raise VnffgdVnfNotFoundException(vnfd_name=vnfd)
                    elif len(vnf_list) > 1:
                        new_mapping[vnfd] = random.choice(vnf_list)
                    else:
                        new_mapping[vnfd] = vnf_list[0]
                # if VNF mapping, validate instances exist and match the VNFD
                else:
                    vnf_vnfd = vnfm_plugin.get_vnf(context, vnf_mapping[vnfd],
                                                   fields='template_id')
                    if vnfd_id != vnf_vnfd:
                        raise VnffgInvalidMappingException(vnfd_name=vnfd)
                    else:
                        new_mapping[vnfd] = vnf_mapping.pop(vnfd)
        return new_mapping

    def _policy_to_acl_criteria(self, template_db, nfp_name):
        template = yaml.load(template_db.template['vnffgd'])
        nfp = template[nfp_name]
        try:
            policy = nfp['properties']['policy']
        except KeyError:
            raise NfpPolicyNotFound(policy=nfp)

        if 'type' in policy:
            if policy['type'] != 'ACL':
                raise NfpPolicyTypeError(type=policy['type'])

        if 'criteria' not in policy:
            raise NfpPolicyCriteriaError(error="Missing criteria in policy")
        match = dict()
        for criteria in policy['criteria']:
            for key, val in criteria.iteritems():
                if key in MATCH_CRITERIA:
                    match.update(self._convert_criteria(key, val))
                else:
                    raise NfpPolicyCriteriaError(error="Unsupported "
                                                       "criteria: "
                                                       "{}".format(key))
        return match

    def _convert_criteria(self, criteria, value):
        """Method is used to convert criteria to proper db value from template

        :param criteria: input criteria name
        :param value: input value
        :return: converted dictionary
        """

        if criteria.endswith('_range'):
            prefix = criteria[:-6]
            criteria_min = prefix + "_min"
            criteria_max = prefix + "_max"
            try:
                min_val, max_val = value.split('-')
            except ValueError:
                raise NfpPolicyCriteriaError(error="Range missing or "
                                                   "incorrect for "
                                                   "%s".format(criteria))
            return {criteria_min: int(min_val), criteria_max: int(max_val)}

        elif criteria.endswith('_name'):
            prefix = criteria[:-5]
            new_value = self._find_id(prefix, value)
            new_name = prefix + "_id"
            return {new_name: new_value}

        else:
            return {criteria: value}

    def _find_id(self, resource, name):
        # this should be overridden with driver call to find ID given name
        # for resource
        return str(uuid.uuid4())

    # called internally, not by REST API
    # instance_id = None means error on creation
    def _create_vnffg_post(self, context, sfc_instance_id,
                           fc_instance_id, vnffg_dict):
        LOG.debug(_('SFC created instance is %s'), sfc_instance_id)
        LOG.debug(_('Flow Classifier created instance is %s'),
                  fc_instance_id)
        nfp_dict = self.get_nfp(context, vnffg_dict['forwarding_paths'])
        sfc_id = nfp_dict['chain_id']
        classifier_id = nfp_dict['classifier_id']
        with context.session.begin(subtransactions=True):
            query = (self._model_query(context, VnffgChain).
                     filter(VnffgChain.id == sfc_id).
                     filter(VnffgChain.status == constants.PENDING_CREATE).
                     one())
            query.update({'instance_id': sfc_instance_id})
            if sfc_instance_id is None:
                query.update({'status': constants.ERROR})
            else:
                query.update({'status': constants.ACTIVE})

            query = (self._model_query(context, VnffgClassifier).
                     filter(VnffgClassifier.id == classifier_id).
                     filter(VnffgClassifier.status ==
                            constants.PENDING_CREATE).
                     one())
            query.update({'instance_id': fc_instance_id})

            if fc_instance_id is None:
                query.update({'status': constants.ERROR})
            else:
                query.update({'status': constants.ACTIVE})

    def _create_vnffg_status(self, context, vnffg):
        nfp = self.get_nfp(context, vnffg['forwarding_paths'])
        chain = self.get_sfc(context, nfp['chain_id'])
        classifier = self.get_classifier(context, nfp['classifier_id'])

        with context.session.begin(subtransactions=True):
            if classifier['status'] == constants.ERROR or chain['status'] ==\
                    constants.ERROR:
                self._update_all_status(context, vnffg['id'], nfp,
                                        constants.ERROR)
            elif classifier['status'] == constants.ACTIVE and \
                    chain['status'] == constants.ACTIVE:
                self._update_all_status(context, vnffg['id'], nfp['id'],
                                        constants.ACTIVE)

    def _update_all_status(self, context, vnffg_id, nfp_id, status):
        with context.session.begin(subtransactions=True):
            (self._model_query(context, Vnffg).
                filter(Vnffg.id == vnffg_id).update({'status': status}))
            (self._model_query(context, VnffgNfp).
                filter(VnffgNfp.id == nfp_id).update({'status': status}))

    def _make_vnffg_dict(self, vnffg_db, fields=None):
        LOG.debug(_('vnffg_db %s'), vnffg_db)
        LOG.debug(_('vnffg_db nfp %s'), vnffg_db.forwarding_paths)
        res = {
            'forwarding_paths': vnffg_db.forwarding_paths[0]['id']
        }
        key_list = ('id', 'tenant_id', 'name', 'description',
                    'vnf_mapping', 'status', 'vnffgd_id')
        res.update((key, vnffg_db[key]) for key in key_list)
        return self._fields(res, fields)

    def _update_vnffg_pre(self, context, vnffg_id):
        vnffg = self.get_vnffg(context, vnffg_id)
        nfp = self.get_nfp(context, vnffg['forwarding_paths'])
        with context.session.begin(subtransactions=True):
            vnffg_db = self._get_vnffg_db(context, vnffg['id'], _ACTIVE_UPDATE,
                                          constants.PENDING_UPDATE)
            self._get_nfp_db(context, nfp['id'], _ACTIVE_UPDATE,
                             constants.PENDING_UPDATE)
        return self._make_vnffg_dict(vnffg_db)

    def _update_vnffg_post(self, context, vnffg_id, new_status):
        vnffg = self.get_vnffg(context, vnffg_id)
        nfp = self.get_nfp(context, vnffg['forwarding_paths'])
        with context.session.begin(subtransactions=True):
            (self._model_query(context, Vnffg).
             filter(Vnffg.id == vnffg['id']).
             filter(Vnffg.status == constants.PENDING_UPDATE).
             update({'status': new_status}))
            (self._model_query(context, VnffgNfp).
             filter(VnffgNfp.id == nfp['id']).
             filter(VnffgNfp.status == constants.PENDING_UPDATE).
             update({'status': new_status}))

    def _get_vnffg_db(self, context, vnffg_id, current_statuses, new_status):
        try:
            vnffg_db = (
                self._model_query(context, Vnffg).
                filter(Vnffg.id == vnffg_id).
                filter(Vnffg.status.in_(current_statuses)).
                with_lockmode('update').one())
        except orm_exc.NoResultFound:
            raise VnffgNotFound(vnffg_id=vnffg_id)
        if vnffg_db.status == constants.PENDING_UPDATE:
            raise VnffgInUse(vnffg_id=vnffg_id)
        vnffg_db.update({'status': new_status})
        return vnffg_db

    def _get_nfp_db(self, context, nfp_id, current_statuses, new_status):
        try:
            nfp_db = (
                self._model_query(context, VnffgNfp).
                filter(VnffgNfp.id == nfp_id).
                filter(VnffgNfp.status.in_(current_statuses)).
                with_lockmode('update').one())
        except orm_exc.NoResultFound:
            raise NfpNotFound(nfp_id=nfp_id)
        if nfp_db.status == constants.PENDING_UPDATE:
            raise NfpInUse(nfp_id=nfp_id)
        nfp_db.update({'status': new_status})
        return nfp_db

    def _get_sfc_db(self, context, sfc_id, current_statuses, new_status):
        try:
            sfc_db = (
                self._model_query(context, VnffgChain).
                filter(VnffgChain.id == sfc_id).
                filter(VnffgChain.status.in_(current_statuses)).
                with_lockmode('update').one())
        except orm_exc.NoResultFound:
            raise SfcNotFound(sfc_id=sfc_id)
        if sfc_db.status == constants.PENDING_UPDATE:
            raise SfcInUse(sfc_id=sfc_id)
        sfc_db.update({'status': new_status})
        return sfc_db

    def _get_classifier_db(self, context, fc_id, current_statuses, new_status):
        try:
            fc_db = (
                self._model_query(context, VnffgClassifier).
                filter(VnffgClassifier.id == fc_id).
                filter(VnffgClassifier.status.in_(current_statuses)).
                with_lockmode('update').one())
        except orm_exc.NoResultFound:
            raise ClassifierNotFound(fc_id=fc_id)
        if fc_db.status == constants.PENDING_UPDATE:
            raise ClassifierInUse(fc_id=fc_id)
        fc_db.update({'status': new_status})
        return fc_db

    def _delete_vnffg_pre(self, context, vnffg_id):
        vnffg = self.get_vnffg(context, vnffg_id)
        nfp = self.get_nfp(context, vnffg['forwarding_paths'])
        chain = self.get_sfc(context, nfp['chain_id'])
        classifier = self.get_classifier(context, nfp['classifier_id'])
        with context.session.begin(subtransactions=True):
            vnffg_db = self._get_vnffg_db(
                context, vnffg['id'], _ACTIVE_UPDATE_ERROR_DEAD,
                constants.PENDING_DELETE)
            self._get_nfp_db(context, nfp['id'], _ACTIVE_UPDATE_ERROR_DEAD,
                             constants.PENDING_DELETE)
            self._get_sfc_db(context, chain['id'], _ACTIVE_UPDATE_ERROR_DEAD,
                             constants.PENDING_DELETE)
            self._get_classifier_db(context, classifier['id'],
                                    _ACTIVE_UPDATE_ERROR_DEAD,
                                    constants.PENDING_DELETE)

        return self._make_vnffg_dict(vnffg_db)

    def _delete_vnffg_post(self, context, vnffg_id, error):
        vnffg = self.get_vnffg(context, vnffg_id)
        nfp = self.get_nfp(context, vnffg['forwarding_paths'])
        chain = self.get_sfc(context, nfp['chain_id'])
        classifier = self.get_classifier(context, nfp['classifier_id'])
        with context.session.begin(subtransactions=True):
            vnffg_query = (
                self._model_query(context, Vnffg).
                filter(Vnffg.id == vnffg['id']).
                filter(Vnffg.status == constants.PENDING_DELETE))
            nfp_query = (
                self._model_query(context, VnffgNfp).
                filter(VnffgNfp.id == nfp['id']).
                filter(VnffgNfp.status == constants.PENDING_DELETE))
            sfc_query = (
                self._model_query(context, VnffgChain).
                filter(VnffgChain.id == chain['id']).
                filter(VnffgChain.status == constants.PENDING_DELETE))
            fc_query = (
                self._model_query(context, VnffgClassifier).
                filter(VnffgClassifier.id == classifier['id']).
                filter(VnffgClassifier.status == constants.PENDING_DELETE))
            match_query = (
                self._model_query(context, ACLMatchCriteria).
                filter(ACLMatchCriteria.vnffgc_id == classifier['id']))
            if error:
                vnffg_query.update({'status': constants.ERROR})
                nfp_query.update({'status': constants.ERROR})
                sfc_query.update({'status': constants.ERROR})
                fc_query.update({'status': constants.ERROR})
            else:
                sfc_query.update({'nfp_id': None})
                match_query.delete()
                fc_query.update({'nfp_id': None})
                nfp_query.delete()
                vnffg_query.delete()
                fc_query.delete()
                sfc_query.delete()

    def _make_template_dict(self, template, fields=None):
        res = {}
        key_list = ('id', 'tenant_id', 'name', 'description', 'template')
        res.update((key, template[key]) for key in key_list)
        return self._fields(res, fields)

    def _make_acl_match_dict(self, acl_match_db):
        key_list = MATCH_DB_KEY_LIST
        return {key: entry[key] for key in key_list for entry in acl_match_db
                if entry[key]}

    def _make_classifier_dict(self, classifier_db, fields=None):
        LOG.debug(_('classifier_db %s'), classifier_db)
        LOG.debug(_('classifier_db match %s'), classifier_db.match)
        res = {
            'match': self._make_acl_match_dict(classifier_db.match)
        }
        key_list = ('id', 'tenant_id', 'instance_id', 'status', 'chain_id',
                    'nfp_id')
        res.update((key, classifier_db[key]) for key in key_list)
        return self._fields(res, fields)

    def _make_nfp_dict(self, nfp_db, fields=None):
        LOG.debug(_('nfp_db %s'), nfp_db)
        res = {}
        key_list = ('id', 'tenant_id', 'symmetrical', 'status', 'chain_id',
                    'classifier_id', 'path_id')
        res.update((key, nfp_db[key]) for key in key_list)
        return self._fields(res, fields)

    def _make_chain_dict(self, chain_db, fields=None):
        LOG.debug(_('chain_db %s'), chain_db)
        res = {}
        key_list = ('id', 'tenant_id', 'symmetrical', 'status', 'chain',
                    'path_id', 'nfp_id', 'instance_id')
        res.update((key, chain_db[key]) for key in key_list)
        return self._fields(res, fields)

    def _get_resource(self, context, model, res_id):
        try:
            return self._get_by_id(context, model, res_id)
        except orm_exc.NoResultFound:
            if issubclass(model, Vnffg):
                raise VnffgNotFound(vnffg_id=res_id)
            elif issubclass(model, VnffgClassifier):
                raise ClassifierNotFound(classifier_id=res_id)
            if issubclass(model, VnffgTemplate):
                raise VnffgdNotFound(vnffgd_id=res_id)
            if issubclass(model, VnffgChain):
                raise SfcNotFound(sfc_id=res_id)
            else:
                raise
