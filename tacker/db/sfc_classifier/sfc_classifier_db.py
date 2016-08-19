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


import uuid
import json
import ast
import sqlalchemy as sa
from sqlalchemy import orm
from sqlalchemy.orm import exc as orm_exc

from tacker.api.v1 import attributes
from tacker import context as t_context
from tacker.db import api as qdbapi
from tacker.db import db_base
from tacker.db import model_base
from tacker.db import models_v1
from tacker.extensions import sfc_classifier
from tacker import manager
from tacker.openstack.common import log as logging
from tacker.openstack.common import uuidutils
from tacker.plugins.common import constants
from sqlalchemy.types import PickleType

LOG = logging.getLogger(__name__)
_ACTIVE_UPDATE = (constants.ACTIVE, constants.PENDING_UPDATE)
_ACTIVE_UPDATE_ERROR_DEAD = (
    constants.PENDING_CREATE, constants.ACTIVE, constants.PENDING_UPDATE,
    constants.ERROR, constants.DEAD)


###########################################################################
# db tables

class SFCClassifier(model_base.BASE, models_v1.HasTenant):
    """SFC Classifier Data Model
    """
    id = sa.Column(sa.String(255),
                   primary_key=True,
                   default=uuidutils.generate_uuid)

    name = sa.Column(sa.String(255), nullable=True)
    description = sa.Column(sa.String(255), nullable=True)

    instance_id = sa.Column(sa.String(255), nullable=True)

    attributes = orm.relationship("SFCCAttribute", backref="sfcclassifier")

    status = sa.Column(sa.String(255), nullable=False)

    # driver to create sfc. e.g. opendaylight
    infra_driver = sa.Column(sa.String(255))

    # link to acl match criteria db table
    acl_match_criteria = orm.relationship('ACLMatchCriteria')

    # chain id to attach classifier to
    chain = sa.Column(sa.String(255), nullable=True)


class SFCCAttribute(model_base.BASE, models_v1.HasId):
    """Represents kwargs necessary for spinning up VM in (key, value) pair
    key value pair is adopted for being agnostic to actuall manager of VMs
    like nova, heat or others. e.g. image-id, flavor-id for Nova.
    The interpretation is up to actual driver of hosting device.
    """
    sfcc_id = sa.Column(sa.String(255), sa.ForeignKey('sfcclassifiers.id'),
                        nullable=False)
    key = sa.Column(sa.String(255), nullable=False)
    # json encoded value. example
    # "nic": [{"net-id": <net-uuid>}, {"port-id": <port-uuid>}]
    value = sa.Column(sa.String(4096), nullable=True)


class ACLMatchCriteria(model_base.BASE, models_v1.HasId):
    """Represents ACL match criteria of a classifier.
    """
    sfcc_id = sa.Column(sa.String(36), sa.ForeignKey('sfcclassifiers.id'))
    source_mac = sa.Column(sa.String(36), nullable=True)
    dest_mac = sa.Column(sa.String(36), nullable=True)
    ethertype = sa.Column(sa.String(36), nullable=True)
    source_ip_prefix = sa.Column(sa.String(36), nullable=True)
    dest_ip_prefix = sa.Column(sa.String(36), nullable=True)
    source_port = sa.Column(sa.Integer, nullable=True)
    dest_port = sa.Column(sa.Integer, nullable=True)
    protocol = sa.Column(sa.Integer, nullable=True)


class SFCCPluginDb(sfc_classifier.SFCCPluginBase, db_base.CommonDbMixin):

    @property
    def _core_plugin(self):
        return manager.TackerManager.get_plugin()

    def __init__(self):
        qdbapi.register_models()
        super(SFCCPluginDb, self).__init__()

    def _get_resource(self, context, model, id):
        try:
            return self._get_by_id(context, model, id)
        except orm_exc.NoResultFound:
            if issubclass(model, SFCClassifier):
                raise sfc_classifier.ClassifierNotFound(sfcc_id=id)
            else:
                raise BaseException

    def _make_attributes_dict(self, attributes_db):
        return dict((attr.key, attr.value) for attr in attributes_db)

    @staticmethod
    def _infra_driver_name(sfcc_dict):
        return sfcc_dict['infra_driver']

    @staticmethod
    def _instance_id(sfcc_dict):
        return sfcc_dict['instance_id']

    # called internally, not by REST API
    def _create_sfc_classifier_pre(self, context, sfcc):
        sfcc = sfcc['sfc_classifier']
        LOG.debug(_('sfc classifier %s'), sfcc)
        tenant_id = self._get_tenant_id_for_create(context, sfcc)
        infra_driver = sfcc.get('infra_driver')
        name = sfcc.get('name')
        description = sfcc.get('description')
        sfcc_id = sfcc.get('id') or str(uuid.uuid4())
        attributes = sfcc.get('attributes', {})
        acl_match_criteria = dict(sfcc.get('match'))
        chain = sfcc.get('chain')

        with context.session.begin(subtransactions=True):

            sfcc_db = SFCClassifier(id=sfcc_id,
                         tenant_id=tenant_id,
                         name=name,
                         description=description,
                         instance_id=None,
                         infra_driver=infra_driver,
                         chain=chain,
                         status=constants.PENDING_CREATE)
            context.session.add(sfcc_db)
            for key, value in attributes.items():
                arg = SFCCAttribute(
                    id=str(uuid.uuid4()), sfc_id=sfc_id,
                    key=key, value=value)
                context.session.add(arg)

            LOG.debug(_('acl_match %s'), acl_match_criteria)
            source_mac = acl_match_criteria.get('source_mac')
            dest_mac = acl_match_criteria.get('dest_mac')
            ethertype = acl_match_criteria.get('ethertype')
            source_ip_prefix = acl_match_criteria.get('source_ip_prefix')
            dest_ip_prefix = acl_match_criteria.get('dest_ip_prefix')
            source_port = acl_match_criteria.get('source_port')
            dest_port = acl_match_criteria.get('dest_port')
            protocol = acl_match_criteria.get('protocol')
            match_db_table = ACLMatchCriteria(
                    id=str(uuid.uuid4()), sfcc_id=sfcc_id,
                    source_mac=source_mac,
                    dest_mac=dest_mac, ethertype=ethertype,
                    source_ip_prefix=source_ip_prefix,
                    dest_ip_prefix=dest_ip_prefix,
                    source_port=source_port, dest_port=dest_port,
                    protocol=protocol)
            context.session.add(match_db_table)

        return self._make_sfc_classifier_dict(sfcc_db)

    # reference implementation. needs to be overridden by subclass
    def create_sfc_classifier(self, context, classifier):
        sfcc_dict = self._create_sfc_classifier_pre(context, classifier)
        # start actual creation of the classifier
        # Waiting for completion of creation should be done in background
        # by another thread if it takes a while.
        instance_id = str(uuid.uuid4())
        sfcc_dict['instance_id'] = instance_id
        self._create_sfc_classifier_post(context, sfcc_dict['id'], instance_id, sfcc_dict)
        self._create_sfc_classifier_status(context, sfcc_dict['id'],
                                           constants.ACTIVE)
        return sfcc_dict

    # called internally, not by REST API
    # instance_id = None means error on creation
    def _create_sfc_classifier_post(self, context, sfcc_id, instance_id,
                         sfcc_dict):
        LOG.debug(_('sfc_classifier_dict %s'), sfcc_dict)
        with context.session.begin(subtransactions=True):
            query = (self._model_query(context, SFCClassifier).
                     filter(SFCClassifier.id == sfcc_id).
                     filter(SFCClassifier.status == constants.PENDING_CREATE).
                     one())
            query.update({'instance_id': instance_id})
            if instance_id is None:
                query.update({'status': constants.ERROR})

            for (key, value) in sfcc_dict['attributes'].items():
                self._sfc_classifier_attribute_update_or_create(context, sfcc_id,
                                                      key, value)

            # trozet I don't think we need to update ACL again here

    def _sfc_classifier_attribute_update_or_create(
            self, context, sfcc_id, key, value):
        arg = (self._model_query(context, SFCCAttribute).
               filter(SFCCAttribute.sfc_id == sfcc_id).
               filter(SFCCAttribute.key == key).first())
        if arg:
            arg.value = value
        else:
            arg = SFCCAttribute(
                id=str(uuid.uuid4()), sfc_id=sfc_id,
                key=key, value=value)
            context.session.add(arg)

    def _create_sfc_classifier_status(self, context, sfcc_id, new_status):
        with context.session.begin(subtransactions=True):
            (self._model_query(context, SFCClassifier).
                filter(SFCClassifier.id == sfcc_id).
                filter(SFCClassifier.status == constants.PENDING_CREATE).
                update({'status': new_status}))

    def _make_sfc_classifier_attrs_dict(self, sfcc_attrs_db):
        return dict((arg.key, arg.value) for arg in sfcc_attrs_db)

    def _make_acl_match_dict(self, acl_match_db):
        key_list = ('source_mac', 'dest_mac', 'ethertype', 'source_ip_prefix',
                    'dest_ip_prefix', 'source_port', 'dest_port', 'protocol')
        return {key: entry[key] for key in key_list for entry in
                acl_match_db if entry[key] is not None}

    def _make_sfc_classifier_dict(self, sfcc_db, fields=None):
        LOG.debug(_('sfcc_db %s'), sfcc_db)
        LOG.debug(_('sfcc_db attributes %s'), sfcc_db.attributes)
        LOG.debug(_('sfcc_db match %s'), sfcc_db.acl_match_criteria)
        res = {
            'attributes': self._make_sfc_classifier_attrs_dict(sfcc_db.attributes),
            'acl_match_criteria':
            self._make_acl_match_dict(sfcc_db.acl_match_criteria)
        }
        key_list = ('id', 'tenant_id', 'name', 'description', 'instance_id',
                    'infra_driver', 'status', 'chain')
        res.update((key, sfcc_db[key]) for key in key_list)
        return self._fields(res, fields)

    def _get_sfc_classifier_db(self, context, sfcc_id, current_statuses, new_status):
        try:
            sfcc_db = (
                self._model_query(context, SFCClassifier).
                filter(SFCClassifier.id == sfcc_id).
                filter(SFCClassifier.status.in_(current_statuses)).
                with_lockmode('update').one())
        except orm_exc.NoResultFound:
            raise sfc_classifier.ClassifierNotFound(sfcc_id=sfcc_id)
        if sfcc_db.status == constants.PENDING_UPDATE:
            raise sfc_classifier.SFCInUse(sfcc_id=sfcc_id)
        sfcc_db.update({'status': new_status})
        return sfcc_db

    def get_sfc_classifier(self, context, sfcc_id, fields=None):
        sfcc_db = self._get_resource(context, SFCClassifier, sfcc_id)
        return self._make_sfc_classifier_dict(sfcc_db, fields)

    def get_sfc_classifiers(self, context, filters=None, fields=None):
        sfccs = self._get_collection(context, SFCClassifier, self._make_sfc_classifier_dict,
                                    filters=filters, fields=fields)
        # Ugly hack to mask internally used record
        return [sfcc for sfcc in sfccs
                if uuidutils.is_uuid_like(sfcc['id'])]

    def _sfc_classifier_exists(self, context, name):
        query = self._model_query(context, SFCClassifier)
        return query.filter(SFCClassifier.name == name).first()

    def sfc_classifier_exists(self, context, name):
        if self._sfc_classifier_exists(context, name):
            raise sfc_classifier.ClassifierAlreadyExists(sfcc_name=name)

    # reference implementation. needs to be overridden by subclass
    def update_sfc_classifier(self, context, sfcc_id, sfcc):
        sfcc_dict = self._update_sfc_classifier_pre(context, sfcc_id)
        # start actual update of classifier
        # waiting for completion of update should be done in the background
        # by another thread if it takes a while
        self._update_sfc_classifier_post(context, sfcc_id, constants.ACTIVE)
        return sfcc_dict

    def _update_sfc_classifier_pre(self, context, sfcc_id):
        with context.session.begin(subtransactions=True):
            sfcc_db = self._get_sfc_classifier_db(
                context, sfcc_id, _ACTIVE_UPDATE, constants.PENDING_UPDATE)
        return self._make_sfc_classifier_dict(sfcc_db)

    def _update_sfc_classifier_post(self, context, sfcc_id, new_status,
                                    new_sfcc_dict=None):
        with context.session.begin(subtransactions=True):
            (self._model_query(context, SFCClassifier).
             filter(SFCClassifier.id == sfcc_id).
             filter(SFCClassifier.status == constants.PENDING_UPDATE).
             update({'status': new_status}))

            sfcc_attrs = new_sfcc_dict.get('attributes', {})
            (context.session.query(SFCCAttribute).
             filter(SFCCAttribute.device_id == sfcc_id).
             filter(~SFCCAttribute.key.in_(sfcc_attrs.keys())).
             delete(synchronize_session='fetch'))

            for (key, value) in sfcc_attrs.items():
                self._sfc_attribute_update_or_create(context, sfcc_id,
                                                     key, value)

    def _delete_sfc_classifier_pre(self, context, sfcc_id):
        with context.session.begin(subtransactions=True):
            sfcc_db = self._get_sfc_classifier_db(
                context, sfcc_id, _ACTIVE_UPDATE_ERROR_DEAD,
                constants.PENDING_DELETE)

        return self._make_sfc_classifier_dict(sfcc_db)

    def _delete_sfc_classifier_post(self, context, sfcc_id, error):
        with context.session.begin(subtransactions=True):
            query = (
                self._model_query(context, SFCClassifier).
                filter(SFCClassifier.id == sfcc_id).
                filter(SFCClassifier.status == constants.PENDING_DELETE))
            if error:
                query.update({'status': constants.ERROR})
            else:
                (self._model_query(context, SFCCAttribute).
                 filter(SFCCAttribute.sfcc_id == sfcc_id).delete())
                (self._model_query(context, ACLMatchCriteria).
                 filter(ACLMatchCriteria.sfcc_id == sfcc_id).delete())
                query.delete()

    # reference implementation. needs to be overridden by subclass
    def delete_sfc_classifier(self, context, sfcc_id):
        self._delete_sfc_classifier_pre(context, sfcc_id)
        # start actual deletion of the classifier.
        # Waiting for completion of deletion should be done in background
        # by another thread if it takes a while.
        self._delete_sfc_classifier_post(context, sfcc_id, False)
