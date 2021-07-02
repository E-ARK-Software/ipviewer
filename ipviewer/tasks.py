import json
import os
import re
import tarfile

import requests
from django.contrib.auth.models import User
from eatb.metadata.mets.ParsedMets import ParsedMets
from eatb.utils.fileutils import list_files_in_dir, get_mime_type
from eatb.xml.xmlvalidation import XmlValidation
from huey import crontab
from huey.contrib.djhuey import task, periodic_task
from huey.contrib.djhuey import signal
from huey.signals import SIGNAL_COMPLETE

from config.configuration import supported_processing_mime_types, mets_entry_pattern, django_service_static_url, \
    input_file_filter_regex, extracted_schemas_directory
from ipviewer.decorators import task_logger
from ipviewer.models import DetectedInformationPackage

import lxml.etree as ET

from ipviewer.util import html_highlight, html_green, html_red, html_bold, read_textfile_from_tar, html_orange, \
    get_schema_location_by_regex, extract_container_entries, get_schema_locations

XSI = "http://www.w3.org/2001/XMLSchema-instance"


@task(context=True)
@task_logger
def validate_and_detect_ips(ips_root_dir, user_id, task=None, task_log=None):  # task parameter is provided by huey context
    task_log.log("Loading information packages from user directory: %s" % ips_root_dir)
    # TODO: implement validation and detection of ips
    u = User.objects.get(id=user_id)
    # delete all user records first
    ret = DetectedInformationPackage.objects.filter(user=u).delete() # noqa
    # read tar files
    all_files_in_user_dir = list_files_in_dir(ips_root_dir)
    container_files_in_user_dir = [f for f in all_files_in_user_dir if re.match(input_file_filter_regex, f)]
    task_log.log("There are %d container files in the user's directory" % len(container_files_in_user_dir))
    for file_in_user_dir in container_files_in_user_dir:
        task_log.log(html_bold("Container file: %s" % file_in_user_dir))
        mime_str = str(get_mime_type(file_in_user_dir))
        if mime_str not in supported_processing_mime_types:
            task_log.log("File skipped: Mime type not supported: %s ")
        else:
            try:
                object_path = os.path.join(ips_root_dir, file_in_user_dir)
                t = tarfile.open(object_path, 'r')
                mets_info_entries = [member for member in t.getmembers() if re.match(mets_entry_pattern, member.name)]
                if len(mets_info_entries) == 1:
                    task_log.log("Root METS file found in container file")
                    root_mets_file_entry = mets_info_entries[0].name
                    root_mets_file_entry_base_dir = os.path.dirname(root_mets_file_entry)
                    root_mets_content = read_textfile_from_tar(t, root_mets_file_entry)
                    parsed_mets = ET.fromstring(bytes(root_mets_content, 'utf-8'))
                    package_mets_schema_location = get_schema_location_by_regex(parsed_mets, r".*/METS/.*")

                    mets_schema_locations = get_schema_locations(parsed_mets)

                    mets_schema_locations_container_entries = [
                        os.path.join(root_mets_file_entry_base_dir, loc) for loc in mets_schema_locations.values()
                    ]
                    # extract schema files to local user directory
                    extract_container_entries(t, mets_schema_locations_container_entries, "%s/schemas" % ips_root_dir)

                    mets_schema_path = os.path.join(ips_root_dir, extracted_schemas_directory, root_mets_file_entry_base_dir, package_mets_schema_location)
                    if package_mets_schema_location:
                        if not package_mets_schema_location.startswith("schemas/"):
                            task_log.error("schema files must be included in the 'schemas' directory")
                        else:
                            xmlval = XmlValidation()
                            try:
                                parsed_mets_schema = ET.parse(mets_schema_path)
                                validation_result = xmlval.validate_XML(parsed_mets, parsed_mets_schema)
                                task_log.success("The root METS file is %s" % "valid"
                                                 if validation_result.valid else "invalid")
                                if len(validation_result.err) > 0:
                                    task_log.log("Errors: " % ", ".join(validation_result.err))
                            except Exception as e:
                                task_log.error("Errors occurred when validating root METS file:")
                                task_log.log("%s" % str(e))
                    else:
                        task_log.warning("Root METS file not validated because no METS schema location was provided")
                    # create record only if OBJID is available
                    if 'OBJID' in parsed_mets.attrib:
                        obj_id = parsed_mets.attrib['OBJID']
                        task_log.log("Object ID: %s" % obj_id)
                        DetectedInformationPackage.objects.create(
                            task_id=task.id,
                            information_package=obj_id,
                            title="First IP",
                            ip_base_dir=root_mets_file_entry_base_dir,
                            ip_filename=file_in_user_dir,
                            user=u,
                            selected=False
                        ).save()
                    else:
                        task_log.log("No object ID defined!")

                t.close()
            except tarfile.TarError:
                print("Error reading tar file: %s" % file_in_user_dir)
    task_log.log("Finished detecting information packages")
    return True


@signal(SIGNAL_COMPLETE)
def task_success(signal, task):  # noqa
    print("task finished: %s" % task.id)
