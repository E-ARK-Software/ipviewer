import os
import re

from eatb.packaging.tar_entry_reader import ChunkedTarEntryReader
import tarfile

XSI = "http://www.w3.org/2001/XMLSchema-instance"


def build_url(protocol, host, port, app_label=None):
    url = "%s://%s%s" % (protocol, host, "" if port in [80, 443] else ":%s" % port)
    if app_label:
        url = "%s/%s" % (url, app_label)
    return url


def read_textfile_from_tar(t, entry, encoding="utf-8"):
    tar_entry_reader = ChunkedTarEntryReader(t)
    chunks = tar_entry_reader.chunks(entry)
    return ''.join([chunk.decode(encoding) for chunk in chunks])


def extract_container_entries(tfile, container_entries, target_dir):
    os.makedirs(target_dir, exist_ok=True)
    for container_entry in container_entries:
        tfile.extract(container_entry, target_dir)


def get_schema_locations(parsed_xml):
    schema_locations = set(parsed_xml.xpath("//*/@xsi:schemaLocation", namespaces={'xsi': XSI}))
    schema_locations_result = {}
    for schema_location in schema_locations:
        namespaces_locations = schema_location.strip().split()
        # Import all fnamspace/schema location pairs
        for namespace, location in zip(*[iter(namespaces_locations)] * 2):
            schema_locations_result[namespace] = location
    return schema_locations_result


def get_schema_location_by_regex(parsed_xml, schema_location_regex):
    schema_locations = get_schema_locations(parsed_xml)
    for namespace, location in schema_locations.items():
        if re.match(schema_location_regex, namespace):
            return location
    return None


class TaskLog(object):

    def __init__(self, log_file_path):
        self.log_file = open(log_file_path, 'w')

    def log(self, msg):
        self.log_file.write("%s\n" % msg)

    def warning(self, msg):
        self.log_file.write("%s: %s\n" % (html_orange("Warning"), msg))

    def error(self, msg):
        self.log_file.write("%s: %s\n" % (html_red("Error"), msg))

    def debug(self, msg):
        self.log_file.write("%s: %s\n" % (html_grey("Debug"), msg))

    def success(self, msg):
        self.log_file.write("%s: %s\n" % (html_green("Success"), msg))

    def close(self):
        if not self.log_file.closed:
            self.log_file.close()


def html_green(text):
    return html_highlight(text, style="color:green")


def html_red(text):
    return html_highlight(text, style="color:red")


def html_orange(text):
    return html_highlight(text, style="color:orange")


def html_grey(text):
    return html_highlight(text, style="color:grey")


def html_bold(text):
    return html_highlight(text, style="font-weight:bold")


def html_highlight(text, style):
    return "<span style='%s'>%s</span>" % (style, text)
