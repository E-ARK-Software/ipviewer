import copy
import fnmatch
import logging
import os
import sys
import traceback

import magic
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.template import loader
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import DetailView
from django.views.generic.base import View
from django.utils import translation
from django.shortcuts import redirect, render
from django.conf import settings
from django_tables2 import RequestConfig, A
import django_tables2 as tables
from eatb.metadata.parsedead import ParsedEad

from eatb.utils.datetime import DT_ISO_FORMAT, DT_ISO_FMT_SEC_PREC, get_date_from_iso_str
from eatb.utils.fileutils import list_files_in_dir

from django.http import HttpResponseNotFound, HttpResponseBadRequest, HttpResponseForbidden, FileResponse, HttpResponse
from eatb.utils.fileutils import fsize, get_mime_type, read_file_content
from eatb.utils.randomutils import randomword

from config.configuration import config_max_http_download, file_size_limit, django_service_ulr, task_logfile_name, \
    mets_entry_pattern, extracted_schemas_directory, ead_entry_pattern, ip_data_path, django_base_service_url, \
    metadata_file_pattern_ead, metadata_file_pattern_premis, ead_md_type, premis_md_type
from ipviewer.context_processors import environment_variables
from ipviewer.models import DetectedInformationPackage
from ipviewer.tasks import validate_and_detect_ips
from django.utils.translation import ugettext_lazy as _
import tarfile
import re
import lxml.etree as ET
from ipviewer.util import read_textfile_from_tar
from eatb.packaging.tar_entry_reader import ChunkedTarEntryReader
from mimetypes import MimeTypes
# , get_schema_location_by_regex, get_schema_locations, extract_container_entries
logger = logging.getLogger(__name__)


def get_representation_label_for_id(root_mets, id):
    for root_structMap in root_mets.iter('{http://www.loc.gov/METS/}structMap'):
        if root_structMap.get('TYPE') == 'PHYSICAL':
            print(root_structMap)
            for div in root_structMap.iter('{http://www.loc.gov/METS/}div'):
                if div.get('ID') == id:
                    return div.get('LABEL')
    return None

def get_ip_overview_context(request):
    user_data_path = os.path.join(ip_data_path, request.user.username)
    vars = environment_variables(request)
    if not vars['selected_ip']:
        return {}
    object_path = os.path.join(user_data_path, vars['selected_ip'].ip_filename)
    tarFile = tarfile.open(object_path, 'r')
    mets_info_entries = [member for member in tarFile.getmembers() if re.match(mets_entry_pattern, member.name)]
    if len(mets_info_entries) == 1:
        logger.info("Root METS file found in container file")
        root_mets_file_entry = mets_info_entries[0].name
        root_mets_file_entry_base_dir = os.path.dirname(root_mets_file_entry)
        root_mets_content = read_textfile_from_tar(tarFile, root_mets_file_entry)
        root_mets = ET.fromstring(bytes(root_mets_content, 'utf-8'))

        all_schemas = []
        for root_structMap in root_mets.iter('{http://www.loc.gov/METS/}structMap'):
            if root_structMap.get('TYPE') == 'PHYSICAL':
                for div in root_structMap.find('{http://www.loc.gov/METS/}div'):
                    label = div.get('LABEL')
                    if label == 'schemas':
                        schemas = get_schemas_section(div, root_mets, root_mets_file_entry_base_dir)
                        all_schemas += [schema['text'] for schema in schemas['nodes']]
                        continue

        #print(root_mets.attrib['OBJID'])
        # for child in parsed_mets:
        #    print(child.tag, child.attrib)
        # for neighbor in parsed_mets.iter('neighbor'):
        #    print(neighbor.attrib)

        overview = {}
        total_size = 0
        total_number_content_files = 0
        content_mime_types = []
        representations = []
        overview['object_id'] = root_mets.attrib['OBJID']

        ead_info_entries = [member for member in tarFile.getmembers() if re.match(ead_entry_pattern, member.name)]
        if len(ead_info_entries) == 1:
            logger.info("EAD file found in container file")
            root_ead_file_entry = ead_info_entries[0].name
            root_ead_file_entry_base_dir = os.path.dirname(root_ead_file_entry)
            root_ead_content = read_textfile_from_tar(tarFile, root_ead_file_entry)
            root_ead = ET.fromstring(bytes(root_ead_content, 'utf-8'))

            found = [element.text for element in root_ead.iter('{http://ead3.archivists.org/schema/}titleproper')]
            #TODO: test for empty
            overview['title'] = found[0]
        else:
            overview['title'] = "Unknown. EAD file missing."

        for root_fileGrp in root_mets.iter('{http://www.loc.gov/METS/}fileGrp'):
            if root_fileGrp.attrib['USE'] == 'representations':
                print(root_fileGrp.tag, root_fileGrp.attrib)
                for root_file in root_fileGrp.iter('{http://www.loc.gov/METS/}file'):
                    FLocat = root_file.find('{http://www.loc.gov/METS/}FLocat')
                    rep_mets_file_entry = FLocat.get("{http://www.w3.org/1999/xlink}href")
                    rep_mets_file_entry = root_mets_file_entry_base_dir + rep_mets_file_entry.strip('.')
                    rep_mets_content = read_textfile_from_tar(tarFile, rep_mets_file_entry)
                    rep_mets = ET.fromstring(bytes(rep_mets_content, 'utf-8'))
                    representation = {}
                    representation['identifier'] = rep_mets.get('OBJID')
                    print(rep_mets)
                    for rep_fileGrp in rep_mets.iter('{http://www.loc.gov/METS/}fileGrp'):
                        print(rep_fileGrp.tag, rep_fileGrp.attrib)
                        for rep_file in rep_fileGrp.iter('{http://www.loc.gov/METS/}file'):
                            mimetype = rep_file.get('MIMETYPE')
                            #print(mimetype)
                            #mime = MimeTypes()
                            #file_mimetype, _ = mime.guess_type(file_url)
                            representation['label'] = get_representation_label_for_id(root_mets,
                                                                                      root_file.get('ID'))
                            #representation['description'] = "From Where???"
                            content_mime_types.append(rep_file.get('MIMETYPE'))
                            total_size += int(rep_file.get('SIZE'))
                            total_number_content_files +=1
                    representations.append(representation)
        overview['representations'] = representations
        total_number_representations = len(representations)
        overview['stats'] = {
                   "total_size": total_size,
                   "total_number_content_files": total_number_content_files,
                   "total_number_representations": total_number_representations,
                   "schemas": ','.join(all_schemas),
                   "content_mime_types": ", ".join(list(set(content_mime_types))),
               }
    return overview


@login_required
def ip_overview(request):
    template = loader.get_template('ipviewer/ip_overview.html')
    ip_overview = get_ip_overview_context(request)
    request.session['overview'] = ip_overview
    return HttpResponse(template.render(context=ip_overview, request=request))


class InformationPackageDetail(DetailView):
    """
    Information Package Detail View
    """
    model = DetectedInformationPackage
    context_object_name = 'ip'
    template_name = 'ipviewer/ip_overview.html'

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(InformationPackageDetail, self).dispatch(*args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(InformationPackageDetail, self).get_context_data(**kwargs)
        # reset selection before the new selection is set
        DetectedInformationPackage.objects.all().update(selected=False)  # noqa
        # register selected ip
        ip = context['object']
        ip.selected = True
        ip.save()
        ip_overview = get_ip_overview_context(self.request)
        context.update(ip_overview)
        #self.request.session['overview'] = ip_overview
        return context


def fileSec_get_file_for_id(fileSec, id):
    for file in fileSec.iter('{http://www.loc.gov/METS/}file'):
        if file.get('ID') == id:
            FLocat = file.find('{http://www.loc.gov/METS/}FLocat')
            fname = FLocat.get("{http://www.w3.org/1999/xlink}href")
            return fname
    #TODO: log
    return None

def mdSec_get_file_for_id(mdSec, id):
    for mdRef in mdSec.iter('{http://www.loc.gov/METS/}mdRef'):
        if mdRef.get('ID') == id:
            fname = mdRef.get("{http://www.w3.org/1999/xlink}href")
            return fname
    #TODO: log
    return None


from urllib.parse import urljoin

def get_schemas_section(div, root_mets, base_dir):
    fileSec = next(root_mets.iter('{http://www.loc.gov/METS/}fileSec'))
    label = div.get('LABEL')
    node = { "text": label,
             "icon": "fa fa-inbox fa-fw",
             "nodes": [] }

    print("%s %s %s %s" % (django_service_ulr, django_base_service_url, ip_data_path, base_dir))

    for fptr in div.iter('{http://www.loc.gov/METS/}fptr'):
        name = fileSec_get_file_for_id(fileSec, fptr.get('FILEID'))
        href = django_service_ulr + '/file-from-ip/' + base_dir + name.strip('.')

        file_node = { "icon": "fa fa-file fa-fw",
                      "text": name,
                      "href": href
                      #"href": "https://google.com"
                    }
        node['nodes'].append(file_node)
    return node

def get_data_section(div, root_mets, base_dir):
    fileSec = next(root_mets.iter('{http://www.loc.gov/METS/}fileSec'))
    label = div.get('LABEL')
    node = { "text": label,
             "icon": "fa fa-inbox fa-fw",
             "nodes": [] }
    for fptr in div.iter('{http://www.loc.gov/METS/}fptr'):
        name = fileSec_get_file_for_id(fileSec, fptr.get('FILEID'))
        href = django_service_ulr + '/file-from-ip/' + base_dir + name.strip('.')
        file_node = { "icon": "fa fa-file fa-fw",
                      "text": name,
                      "href": href
                    }
        node['nodes'].append(file_node)
    return node


def get_metadata_section(div, root_mets, base_dir):
    sections = [section for section in root_mets.iter('{http://www.loc.gov/METS/}dmdSec')]
    sections += [section for section in root_mets.iter('{http://www.loc.gov/METS/}amdSec')]
    #amdSec = next(root_mets.iter('{http://www.loc.gov/METS/}amdSec'))
    #dmdSec = next(root_mets.iter('{http://www.loc.gov/METS/}dmdSec'))
    label = div.get('LABEL')
    node = { "text": label,
             "icon": "fa fa-inbox fa-fw",
             "nodes": [] }
    for fptr in div.iter('{http://www.loc.gov/METS/}fptr'):
        for section in sections:
            name = mdSec_get_file_for_id(section, fptr.get('FILEID'))
            if name:
                href = django_service_ulr + '/file-from-ip/' + base_dir + name.strip('.')
                #if name.endswith('premis.xml'):
                #    print("Found premis")
                file_node = {"icon": "fa fa-file fa-fw",
                             "text": name,
                             "href": href
                             }
                node['nodes'].append(file_node)
                break
    return node

def get_representation_section(div, root_mets, tarFile, root_mets_file_entry_base_dir):
    if type(root_mets) == tuple:
        e = root_mets[0]
    else:
        e = root_mets
    fileSec = next(e.iter('{http://www.loc.gov/METS/}fileSec'))
    label = div.get('LABEL')
    rep_node = {}
    for fptr in div.iter('{http://www.loc.gov/METS/}fptr'):
        file_name = fileSec_get_file_for_id(fileSec, fptr.get('FILEID'))
        if file_name is not None:
            if file_name.endswith('METS.xml'):
                rep_mets_file_entry = root_mets_file_entry_base_dir + file_name.strip('.')
                rep_mets_content = read_textfile_from_tar(tarFile, rep_mets_file_entry)
                rep_mets = ET.fromstring(bytes(rep_mets_content, 'utf-8'))
                representation = {}
                rep_node = {"icon": "fa fa-ibox fa-fw",
                             "text": rep_mets.get('OBJID'),
                             "nodes": []
                             }
                for rep_structMap in rep_mets.iter('{http://www.loc.gov/METS/}structMap'):
                    if rep_structMap.get('TYPE') == 'PHYSICAL':
                        for div in rep_structMap.find('{http://www.loc.gov/METS/}div'):
                            label = div.get('LABEL')
                            if label == 'data':
                                data = get_data_section(div, rep_mets, os.path.dirname(rep_mets_file_entry))
                                rep_node['nodes'].append(data)
                                continue
                            if label == 'schemas':
                                schemas = get_schemas_section(div, rep_mets, os.path.dirname(rep_mets_file_entry))
                                rep_node['nodes'].append(schemas)
                                continue
                            if label == 'metadata':
                                metadata = get_metadata_section(div, rep_mets, os.path.dirname(rep_mets_file_entry))
                                # Read premis and create premis entry
                                for entry in metadata['nodes']:
                                    if entry['text'].endswith('premis.xml'):
                                        premis_file_entry = os.path.dirname(rep_mets_file_entry) + entry['text'].strip(".")
                                        print(premis_file_entry)
                                        rep_premis_content = read_textfile_from_tar(tarFile, premis_file_entry)
                                        rep_premis = ET.fromstring(bytes(rep_premis_content, 'utf-8'))
                                        metadata['premis'] = {'representations': getRepresentations(rep_premis),
                                                              'events': getPemisEvents(rep_premis)}
                                rep_node['nodes'].append(metadata)
                                continue
    return rep_node


def getRepresentations(rep_premis):
    representations = []
    for rep_object in rep_premis.iter('{info:lc/xmlns/premis-v2}object'):
        rep = getRepresentation(rep_object)
        if rep is not None:
            representations.append(rep)
    return representations


def getRepresentation(rep_object):
    if rep_object.get('{http://www.w3.org/2001/XMLSchema-instance}type') == 'file':
        return {'xmlId': rep_object.get('xmlID'),
                'objectId': getRepresentationObjectId(rep_object),
                'relationship': getObjectRelationship(rep_object) }
    return None

def getRepresentationObjectId(rep_object):
    rep_object_id = rep_object.find('{info:lc/xmlns/premis-v2}objectIdentifier')
    if rep_object_id is not None:
        rep_object_id_type = rep_object_id.find('{info:lc/xmlns/premis-v2}objectIdentifierType')
        rep_object_id_value = rep_object_id.find('{info:lc/xmlns/premis-v2}objectIdentifierValue')
        return {'type': rep_object_id_type.text,
                'value': rep_object_id_value.text }
    return None

def getObjectRelationship(rep_object):
    rep_object_relationship = rep_object.find('{info:lc/xmlns/premis-v2}relationship')
    if rep_object_relationship is not None:
        rep_object_relationship_type = rep_object_relationship.find(
            '{info:lc/xmlns/premis-v2}relationshipType')
        rep_object_relationship_subtype = rep_object_relationship.find(
            '{info:lc/xmlns/premis-v2}relationshipSubType')
        return {'type': rep_object_relationship_type.text,
                'subtype': rep_object_relationship_subtype.text,
                'objectId': getRelatedObjectId(rep_object_relationship),
                'eventId': getRelatedEventId(rep_object_relationship)}
    return None


def getRelatedObjectId(rep_object_relationship):
    rep_object_relationship_related_obj_id = rep_object_relationship.find(
        '{info:lc/xmlns/premis-v2}relatedObjectIdentification')
    if rep_object_relationship_related_obj_id is not None:
        rep_object_relationship_related_obj_id_type = rep_object_relationship_related_obj_id.find(
            '{info:lc/xmlns/premis-v2}relatedObjectIdentifierType')
        rep_object_relationship_related_obj_id_value = rep_object_relationship_related_obj_id.find(
            '{info:lc/xmlns/premis-v2}relatedObjectIdentifierValue')
        rep_object_relationship_related_obj_sequence = rep_object_relationship_related_obj_id.find(
            '{info:lc/xmlns/premis-v2}relatedObjectSequence')
        return {'type': rep_object_relationship_related_obj_id_type.text,
                'value': rep_object_relationship_related_obj_id_value.text,
                'sequence': rep_object_relationship_related_obj_sequence.text}
    return None


def getRelatedEventId(rep_object_relationship):
    rep_object_relationship_related_event_id = rep_object_relationship.find(
        '{info:lc/xmlns/premis-v2}relatedEventIdentification')
    if rep_object_relationship_related_event_id is not None:
        rep_object_relationship_related_event_id_type = rep_object_relationship_related_event_id.find(
            '{info:lc/xmlns/premis-v2}relatedEventIdentifierType')
        rep_object_relationship_related_event_id_value = rep_object_relationship_related_event_id.find(
            '{info:lc/xmlns/premis-v2}relatedEventIdentifierValue')
        rep_object_relationship_related_event_sequence = rep_object_relationship_related_event_id.find(
            '{info:lc/xmlns/premis-v2}relatedEventSequence')
        return {'type': rep_object_relationship_related_event_id_type.text,
                'value': rep_object_relationship_related_event_id_value.text,
                'sequence': rep_object_relationship_related_event_sequence.text }
    return None


def getPremisEventId(rep_premis_event):
    rep_premis_event_id = rep_premis_event.find('{info:lc/xmlns/premis-v2}eventIdentifier')
    if rep_premis_event_id is not None:
        rep_premis_event_id_type = rep_premis_event_id.find(
            '{info:lc/xmlns/premis-v2}eventIdentifierType')
        rep_premis_event_id_value = rep_premis_event_id.find(
            '{info:lc/xmlns/premis-v2}eventIdentifierValue')
        return {'type': rep_premis_event_id_type.text,
                'value': rep_premis_event_id_value.text}
    return None

def getPemisEvents(rep_premis):
    events = []
    for rep_premis_event in rep_premis.iter('{info:lc/xmlns/premis-v2}event'):
        rep_premis_event_datetime = rep_premis_event.find('{info:lc/xmlns/premis-v2}eventDateTime')
        rep_premis_event_type = rep_premis_event.find('{info:lc/xmlns/premis-v2}eventType')
        events.append({"datetime": rep_premis_event_datetime.text,
                       "type": rep_premis_event_type.text,
                       'id': getPremisEventId(rep_premis_event),
                       'linking_agent_id': getPremisLinkingAgentId(rep_premis_event),
                       'linking_object_id': getPremisLinkingObjectId(rep_premis_event)
        })
    return events

def getPremisLinkingObjectId(rep_premis_event):
    rep_premis_linking_object_identifier = rep_premis_event.find(
        '{info:lc/xmlns/premis-v2}linkingObjectIdentifier')
    if rep_premis_linking_object_identifier is not None:
        rep_premis_linking_object_identifier_type = rep_premis_linking_object_identifier.find(
            '{info:lc/xmlns/premis-v2}linkingObjectIdentifierType')
        rep_premis_linking_object_identifier_value = rep_premis_linking_object_identifier.find(
            '{info:lc/xmlns/premis-v2}linkingObjectIdentifierValue')
        return {'type': rep_premis_linking_object_identifier_type.text,
                'value': rep_premis_linking_object_identifier_value.text}
    return None

def getPremisLinkingAgentId(rep_premis_event):
    rep_premis_linking_agent_identifier = rep_premis_event.find('{info:lc/xmlns/premis-v2}linkingAgentIdentifier')
    if rep_premis_linking_agent_identifier is not None:
        rep_premis_linking_agent_identifier_type = rep_premis_linking_agent_identifier.find(
            '{info:lc/xmlns/premis-v2}linkingAgentIdentifierType')
        rep_premis_linking_agent_identifier_value = rep_premis_linking_agent_identifier.find(
            '{info:lc/xmlns/premis-v2}linkingAgentIdentifierValue')
        return {'type': rep_premis_linking_agent_identifier_type.text,
                'value': rep_premis_linking_agent_identifier_value.text}
    return None

def openInformationPackage(request, username):
    user_data_path = os.path.join(ip_data_path, username)
    vars = environment_variables(request)
    selected_ip = vars['selected_ip']
    object_path = os.path.join(user_data_path, selected_ip.ip_filename)
    t = tarfile.open(object_path, 'r')
    return t

def readRootMetsFromIP(tarFile):
    mets_info_entries = [member for member in tarFile.getmembers() if re.match(mets_entry_pattern, member.name)]
    if len(mets_info_entries) == 1:
        logger.info("Root METS file found in container file")
        root_mets_file_entry = mets_info_entries[0].name
        root_mets_file_entry_base_dir = os.path.dirname(root_mets_file_entry)
        root_mets_content = read_textfile_from_tar(tarFile, root_mets_file_entry)
        root_mets = ET.fromstring(bytes(root_mets_content, 'utf-8'))
        return (root_mets, root_mets_file_entry_base_dir)
    return None

@login_required
def ip_structure(request, tab):
    vars = environment_variables(request)
    if not vars['selected_ip']:
        return {}
    selected_ip = vars['selected_ip']
    template = loader.get_template('ipviewer/ip_structure.html')
    context = get_ip_structure(request)
    context["tab"] = tab
    return HttpResponse(template.render(context=context, request=request))

def get_ip_structure(request):
    username = request.user.username
    vars = environment_variables(request)
    if not vars['selected_ip']:
        return {}
    selected_ip = vars['selected_ip']

    logical_view_data = []
    tarFile = openInformationPackage(request, username)
    root_mets, root_mets_file_entry_base_dir = readRootMetsFromIP(tarFile)
    if root_mets is not None:
        # iterate structMap get ids and reference in dmdSec/amdSec/fileSec
        obj_id = root_mets.attrib['OBJID']
        logical_view_section = {
            "text": obj_id,
            "icon": "fa fa-archive fa-fw",
            "nodes": []
        }
        logical_view_data.append(logical_view_section)
        representations = {"text": "representations",
                           "icon": "fa fa-inbox fa-fw",
                           "nodes": []}
        for root_structMap in root_mets.iter('{http://www.loc.gov/METS/}structMap'):
            if root_structMap.get('TYPE') == 'PHYSICAL':
                for div in root_structMap.find('{http://www.loc.gov/METS/}div'):
                    label = div.get('LABEL')
                    if label == 'schemas':
                        schemas = get_schemas_section(div, root_mets, root_mets_file_entry_base_dir)
                        logical_view_section['nodes'].append(schemas)
                        continue
                    if label == 'metadata':
                        metadata = get_metadata_section(div, root_mets, root_mets_file_entry_base_dir)
                        logical_view_section['nodes'].append(metadata)
                        continue
                    representation = get_representation_section(div, root_mets, tarFile, root_mets_file_entry_base_dir)
                    representations['nodes'].append(representation)
        logical_view_section['nodes'].append(representations)
    physical_view_data = [
        {
            "text": "Container files",
            "icon": "fa fa-boxes fa-fw",
            "nodes": [
                {
                    "text": selected_ip.ip_filename,
                    "icon": "fa fa-archive fa-fw",
                    "nodes": logical_view_section['nodes'],
                }
            ]
        }
    ]
    new_physical_view_data = copy.deepcopy(physical_view_data)
    for logical_package_node in logical_view_data:
        package_item_nodes = logical_package_node['nodes']
        for folder_node in package_item_nodes:
            if folder_node['text'] == 'metadata':
                item_nodes = folder_node['nodes']
                for i, item_node in enumerate(item_nodes):
                    if fnmatch.fnmatch(item_node['text'], metadata_file_pattern_ead):
                        item_node['text'] = ead_md_type
                        item_node['href'] = item_node['href'].replace("file-from-ip", "get-basic-metadata")
                    elif fnmatch.fnmatch(item_node['text'], metadata_file_pattern_premis):
                        item_node['text'] = premis_md_type
                        item_node['href'] = item_node['href'].replace("file-from-ip", "get-basic-metadata")
                    else:
                        item_node['class'] = "hidden"
            elif folder_node['text'] == 'schemas':
                folder_node['class'] = "hidden"
    context = {
        "logical_view_data": logical_view_data,
        "physical_view_data": new_physical_view_data,
    }
    return context


@login_required
def input_data(request, tab):
    template = loader.get_template('ipviewer/input_data.html')

    # table data
    u = User.objects.get(id=request.user.id)
    queryset = DetectedInformationPackage.objects.filter(user=u)  # noqa
    ip_table = InformationPackageTable(queryset)
    RequestConfig(request, paginate={'per_page': 8}).configure(ip_table)

    context = {
        'ip_table': ip_table,
        "django_service_ulr": django_service_ulr,
        "task_logfile_name": task_logfile_name,
        "tab": tab
    }
    return HttpResponse(template.render(context=context, request=request))


@login_required
def representations(request, tab):
    vars = environment_variables(request)
    if not vars['selected_ip']:
        return {}
    template = loader.get_template('ipviewer/representations.html')
    events = {}

    tarFile = openInformationPackage(request, request.user.username)
    root_mets, root_mets_file_entry_base_dir = readRootMetsFromIP(tarFile)
    if root_mets is not None:
        for root_structMap in root_mets.iter('{http://www.loc.gov/METS/}structMap'):
            if root_structMap.get('TYPE') == 'PHYSICAL':
                for div in root_structMap.find('{http://www.loc.gov/METS/}div'):
                    representation = get_representation_section(div, root_mets, tarFile, root_mets_file_entry_base_dir)
                    if 'nodes' in representation:
                        for node in representation['nodes']:
                            if 'metadata' in node['text']:
                                if 'premis' in node:
                                    premis = node['premis']
                                    if 'events' in premis:
                                        for event in premis['events']:
                                            events[event['datetime']] = event['type']
    version_label = 0
    inventory = {"versions": {}}
    for datetime in events:
        inventory['versions'][str(version_label)] = {
            "created": datetime,
            "message": events[datetime]
        }
        version_label+=1

    version_timeline_data = [
        {
            "id": int(key),
            "content": "%s (%s)" % (val["message"], key),
            "start": val["created"],
            "className": "myClassName"
        }
        for key, val in inventory["versions"].items()
    ]
    times = [val["created"] for key, val in inventory["versions"].items()]
    times.sort()
    if len(times) > 1:
        min_dtstr = times[0]
        max_dtstr = times[len(times) - 1]
        min_dt = get_date_from_iso_str(min_dtstr, DT_ISO_FMT_SEC_PREC)
        max_dt = get_date_from_iso_str(max_dtstr, DT_ISO_FMT_SEC_PREC)
        delta = max_dt - min_dt
        scale = ("seconds", delta.seconds) if delta.seconds < 60 \
            else ("minutes", int(delta.seconds / 60)) if delta.seconds < 3600 \
            else ("hours", int(delta.seconds / 3600)) if delta.seconds < 86400 \
            else ("days", delta.days) if delta.seconds < 2592000 \
            else ("months", int(delta.days / 30)) if delta.seconds < 31536000 \
            else ("years", int(delta.days / 365))
        scale_unit, scale_value = scale
    else:
        min_dtstr = max_dtstr = times[0]
        scale_unit = "days"
        scale_value = "3"
    context = {
        "version_timeline_data": version_timeline_data,
        "scale_unit": scale_unit,
        "scale_value": (scale_value * 10),
        "min_dt": min_dtstr,
        "max_dt": max_dtstr,
        "tab": tab,
        "demo": bool(request.GET.get('demo'))
    }
    return HttpResponse(template.render(context=context, request=request))

@csrf_exempt
def representation_dependency_graph(request):  # noqa
    template = loader.get_template('ipviewer/representations.html')
    events = {}
    vars = environment_variables(request)
    selected_ip = vars['selected_ip']
    tarFile = openInformationPackage(request, request.user.username)
    root_mets = readRootMetsFromIP(tarFile)

    # TODO: read migration paths from PREMIS file

    try:
        if root_mets is not None:
            root_structs = root_mets[0].iter('{http://www.loc.gov/METS/}structMap')
            for root_structMap in root_structs:
                if root_structMap.get('TYPE') == 'PHYSICAL':
                    for div in root_structMap.find('{http://www.loc.gov/METS/}div'):
                        mets_info_entries = [member for member in tarFile.getmembers() if
                                             re.match(mets_entry_pattern, member.name)]
                        root_mets_file_entry = mets_info_entries[0].name
                        root_mets_file_entry_base_dir = os.path.dirname(root_mets_file_entry)
                        representation = get_representation_section(div, root_mets, tarFile, root_mets_file_entry_base_dir)
                        if 'nodes' in representation:
                            for node in representation['nodes']:
                                if 'metadata' in node['text']:
                                    if 'premis' in node:
                                        premis = node['premis']
                                        if 'events' in premis:
                                            for event in premis['events']:
                                                events[event['datetime']] = event['type']
    except Exception as error:
        print("Error: %s" % str(error))


    nodes = [
        {"id": 1, "label": "MS Word 2003 XML Document (SIP)", "shape": "box"},
        {"id": 2, "label": "PDF document (ingest)", "shape": "box"},
        {"id": 3, "label": "PDF/A document (migration)", "shape": "box"},
    ]
    edges = [
        {"from": 1, "to": 2, "arrows": "to", "label": "Adobe Acrobat Office PDF Maker  v9.0"},
        {"from": 2, "to": 3, "arrows": "to", "label": "Ghostscript v1.3"},
    ]
    return JsonResponse({"nodes": nodes, "edges": edges}, status=200)

@login_required
@csrf_exempt
def upload(request):
    if request.method == "POST":
        posted_files = request.FILES
        if 'file_data' not in posted_files:
            return JsonResponse({'error': "No files available"}, status=500)
        else:
            data_path = ip_data_path
            if not os.path.exists(data_path):
                msg = "The data directory does not exist: %s.\n" \
                      "Please check 'ip_data_path' parameter in settings.cfg." % data_path
                return JsonResponse({'error': msg}, status=500)
            if not os.access(data_path, os.W_OK):
                msg = "Unable to write to data directory: %s.\n" \
                      "Please check permissions." % data_path
                return JsonResponse({'error': msg}, status=500)
            user_data_path = os.path.join(data_path, request.user.username)
            os.makedirs(user_data_path, exist_ok=True)
            file_data = posted_files['file_data']
            filename = file_data.name
            file_path = os.path.join(user_data_path, filename)
            with open(file_path, 'wb+') as destination:
                for chunk in posted_files['file_data'].chunks():
                    destination.write(chunk)
            # untar archive for file visualization
            # if file_path.endswith("tar"):
            #     tar = tarfile.open(file_path, "r:")
            #     tar.extractall(user_data_path)
            #     tar.close()
            file_upload_resp = {
                "ver": "1.0",
                "ret": True,
                "errcode": 0,
                "data": {
                    "status": "upload success",
                    "originalFilename": filename,
                    "fileName": filename,
                }
            }
            return JsonResponse(file_upload_resp, status=201)
    else:
        template = loader.get_template('ipviewer/input_data.html')
    context = {
    }
    return HttpResponse(template.render(context=context, request=request))


@login_required
@csrf_exempt
def user_file_resource(request, file_path):
    if file_path.startswith("/"):
        return JsonResponse({'error': "File path must be relative"}, status=400)
    data_path = ip_data_path
    user_data_file_path = os.path.join(data_path, request.user.username, file_path)
    if not os.path.exists(user_data_file_path):
        msg = "The file does not exist: %s" % user_data_file_path
        return JsonResponse({'error': msg}, status=404)
    if request.method == "GET":
        return read_file(user_data_file_path)
    elif request.method == "POST":
        # POST is translated to delete (kv-file-explorer triggers post request for delete action)
        if not os.access(user_data_file_path, os.W_OK):
            msg = "Permission denied, file cannot be deleted: %s" % user_data_file_path
            return JsonResponse({'error': msg}, status=401)
        os.unlink(user_data_file_path)
        if not os.path.exists(user_data_file_path):
            return JsonResponse({'success': True}, status=200)
        else:
            msg = "Unable to remove file: %s" % user_data_file_path
            return JsonResponse({'error': msg}, status=500)


def search(search_dict, field):
    """
    Takes a dict with nested lists and dicts,
    and searches all dicts for a key of the field
    provided.
    """
    fields_found = []
    if isinstance(search_dict, dict):
        for key, value in search_dict.items():
            if key == field:
                fields_found.append(value)
            elif isinstance(value, dict):
                results = search(value, field)
                for result in results:
                    fields_found.append(result)
            elif isinstance(value, list):
                for item in value:
                    more_results = search(item, field)
                    for another_result in more_results:
                        fields_found.append(another_result)
    elif isinstance(search_dict, list):
        for item in search_dict:
            more_results = search(item, field)
            for another_result in more_results:
                fields_found.append(another_result)

    return fields_found

def get_basic_metadata(request, file_path):
    user_data_path = os.path.join(ip_data_path, request.user.username)
    vars = environment_variables(request)
    if not vars['selected_ip']:
        return {}
    selected_ip = vars['selected_ip']
    print(file_path)
    archive_file_path = os.path.join(user_data_path, selected_ip.ip_filename)
    t = tarfile.open(archive_file_path, 'r')
    file_content = read_textfile_from_tar(t, file_path)
    tmp_file_path = "/tmp/%s" % randomword(10)
    res_events = []
    try:
        title = ""
        date = ""
        with open(tmp_file_path, 'w') as tmp_file:
            tmp_file.write(file_content)
        if fnmatch.fnmatch(file_path, metadata_file_pattern_ead):
            pead = ParsedEad("/tmp", tmp_file_path)
            dao_elements = pead.get_dao_elements()
            actual = pead.ead_tree.getroot().tag
            unit_titles = []
            unit_dates = []
            for dao_elm in dao_elements:
                unit_titles.append(pead._first_md_val_ancpath(dao_elm, "unittitle"))
                unit_dates.append(pead._first_md_val_ancpath(dao_elm, "unitdate"))
            title = unit_titles[0]
            date = unit_dates[0]
            events = ""
        elif fnmatch.fnmatch(file_path, metadata_file_pattern_premis):
            structure = get_ip_structure(request)
            logical_view = search(structure, "logical_view_data")
            events = search(logical_view, "events")
            for event in events:
                if len(event):
                    res_events.append({ 'type': event[0]['type'], 'datetime': event[0]['datetime'], 'agent': event[0]['linking_agent_id']['value']})
            title = "Root PREMIS"
            date = "20.09.2017"

        md_type = ead_md_type if fnmatch.fnmatch(file_path, metadata_file_pattern_ead)  \
            else premis_md_type if fnmatch.fnmatch(file_path, metadata_file_pattern_premis) else "Other"

        return JsonResponse({'success': True, 'type': md_type, 'title': title, 'date': date, 'events': res_events, 'file_path': file_path}, status=200)
    except Exception as error:
        logger.exception(error)
        return JsonResponse({'success': False, 'error': str(error)}, status=500)


def file_from_ip(request, file_path):
    user_data_path = os.path.join(ip_data_path, request.user.username)
    vars = environment_variables(request)
    if not vars['selected_ip']:
        return {}
    archive_file_path = os.path.join(user_data_path, vars['selected_ip'].ip_filename)
    t = tarfile.open(archive_file_path, 'r')
    info = t.getmember(file_path)
    f = t.extractfile(info)
    start_bytes = f.read(256)

    inst = ChunkedTarEntryReader(t)
    magic_mime_detect = magic.Magic(mime=True)
    mime = magic_mime_detect.from_buffer(start_bytes)

    return HttpResponse(inst.chunks(file_path), content_type=mime)

def read_file(file_path):
    if not os.path.exists(file_path):
        return HttpResponseNotFound("File not found %s" % file_path)
    elif not os.path.isfile(file_path):
        return HttpResponseBadRequest("Not a file")
    else:
        file_size = fsize(file_path)
        mime = get_mime_type(file_path)
        if file_size > config_max_http_download:
            return HttpResponseForbidden(
                "Size of requested file exceeds limit (file size %d > %d)" % (file_size, config_max_http_download))
        if file_path.lower().endswith(('.tar', '.tar.gz', 'zip')):
            stream = open(file_path, 'rb')
            response = FileResponse(stream, content_type=mime)
            response['Content-Disposition'] = "attachment; filename=%s" % os.path.basename(file_path)
            return response
        if file_size <= file_size_limit:
            file_content = read_file_content(file_path)
            if mime == "text/plain":
                mime = "text/plain;charset=utf-8"
            return HttpResponse(file_content, content_type=mime)
        else:
            return HttpResponseForbidden("Size of requested file exceeds limit (file size %d > %d)" %
                                         (file_size, file_size_limit))


@login_required
def user_dir_files(request):
    data_path = ip_data_path
    user_data_path = os.path.join(data_path, request.user.username)
    if not os.path.exists(data_path):
        msg = "The data directory does not exist: %s.\n" \
              "Please check 'ip_data_path' parameter in settings.cfg." % data_path
        return JsonResponse({'error': msg}, status=500)
    user_files = list_files_in_dir(user_data_path)
    user_files.remove(task_logfile_name)
    return JsonResponse({"data": user_files}, status=200)


class ActivateLanguageView(View):
    language_code = ''
    redirect_to = ''

    def get(self, request, *args, **kwargs):  # noqa
        self.redirect_to = request.META.get('HTTP_REFERER')
        self.language_code = kwargs.get('language_code')
        translation.activate(self.language_code)
        request.session[translation.LANGUAGE_SESSION_KEY] = self.language_code
        response = redirect(request.META.get('HTTP_REFERER', request.path_info))
        response.set_cookie(settings.LANGUAGE_COOKIE_NAME, self.language_code)
        return response


class InformationPackageTable(tables.Table):
    information_package = tables.Column(orderable=False, verbose_name=_('Detected Information Package'))
    selected = tables.LinkColumn('ip_overview_select', kwargs={'pk': A('pk')}, verbose_name=_('Selection'),
                                 orderable=False)

    class Meta:
        model = DetectedInformationPackage
        fields = ('information_package',)
        attrs = {'class': 'table table-striped table-bordered table-condensed'}
        row_attrs = {'data-id': lambda record: record.pk}

    @staticmethod
    def render_selected(value):
        print(type(value))
        if value:
            return mark_safe(
                '<i class="far fa-check-square"></i>'
            )
        else:
            return mark_safe(
                '<button type="button" class="btn btn-primary btn-xs">Select</button>'
            )


@login_required
@csrf_exempt
def validate_load_result(request):
    # start detection as background task
    user_data_path = os.path.join(ip_data_path, request.user.username)
    user_id = request.user.id
    task_result = validate_and_detect_ips(user_data_path, user_id)
    print("task id: %s" % task_result.id)
    task_result()

    # table data
    u = User.objects.get(id=request.user.id)
    queryset = DetectedInformationPackage.objects.filter(user=u)  # noqa
    ip_table = InformationPackageTable(queryset)
    RequestConfig(request, paginate={'per_page': 8}).configure(ip_table)
    context = {
        'ip_table': ip_table,
        "django_service_ulr": django_service_ulr,
        "task_logfile_name": task_logfile_name
    }
    return render(request, 'ipviewer/validate_load_result.html', context)


@login_required
@csrf_exempt
def reload_table(request):
    u = User.objects.get(id=request.user.id)
    queryset = DetectedInformationPackage.objects.filter(user=u)  # noqa
    table = InformationPackageTable(queryset)
    RequestConfig(request, paginate={'per_page': 8}).configure(table)
    context = {
        'informationpackage': table,
    }
    return render(request, 'ipviewer/ipstable.html', context=context)
