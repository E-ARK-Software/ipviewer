#!/usr/bin/env python
# coding=UTF-8
import sys
import os

from ipviewer.util import build_url

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))  # noqa: E402
import string
import configparser

import logging
logger = logging.getLogger(__name__)


root_dir = os.path.split(os.path.abspath(os.path.dirname(__file__)))[0]

# ATTENTION: Environment variables overrule config file settings in settings/settings.cfg
# configuration file
config = configparser.ConfigParser()
config['DEFAULT'] = {}
config.sections()
config.read(os.path.join(root_dir, 'settings/settings.cfg'))

task_logfile_name = config.get('logs', 'task_logfile_name')

# version
logo = config.get('application', 'logo')
sw_version = config.get('application', 'sw_version')
sw_version_date = config.get('application', 'sw_version_date')
app_label = config.get('application', 'app_label')
app_base = config.get('application', 'app_base')


backend_api_key = config.get('system', "backend_api_key")

# logfiles
logfile_ui = config.get('logs', 'logfile_ui')

# django
django_secret_key = config.get('server', 'django_secret_key')
django_service_protocol = config.get('server', 'django_service_protocol')
django_service_host = config.get('server', 'django_service_host')
django_service_port = int(config.get('server', 'django_service_port'))
django_base_service_url = build_url(django_service_protocol, django_service_host, django_service_port)
django_service_ulr = "%s/%s" % (django_base_service_url, app_base)
django_service_static_url = "%s/static" % django_base_service_url

# data directories
ip_data_path = config.get('paths', 'ip_data_path')
extracted_schemas_directory = config.get('paths', 'extracted_schemas_directory')

# size limit for direct file display
file_size_limit = config.getint('limits', 'config_max_filesize_viewer')
config_max_http_download = config.getint('limits', 'config_max_http_download')
config_max_http_upload = config.getint('limits', 'config_max_http_upload')

input_file_filter_regex = config.get('filetype', 'input_file_filter_regex')
allowed_upload_mime_types = list(map(str.strip, config.get('filetype', 'allowed_upload_mime_types').split(sep=",")))
supported_processing_mime_types = list(map(str.strip, config.get('filetype', 'supported_processing_mime_types').split(sep=",")))

mets_entry_pattern = config.get('filetype', 'mets_entry_pattern')
ead_entry_pattern = config.get('filetype', 'ead_entry_pattern')
premis_entry_pattern = config.get('filetype', 'premis_entry_pattern')

def log_current_configuration():
    logger.info("Web-UI: %s://%s:%s" % (django_service_protocol, django_service_host, django_service_port))

