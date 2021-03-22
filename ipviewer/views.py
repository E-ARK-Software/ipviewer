import logging
import os

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

from eatb.utils.datetime import DT_ISO_FORMAT, get_date_from_iso_str
from eatb.utils.fileutils import list_files_in_dir

from django.http import HttpResponseNotFound, HttpResponseBadRequest, HttpResponseForbidden, FileResponse, HttpResponse
from eatb.utils.fileutils import fsize, get_mime_type, read_file_content

from config.configuration import config_max_http_download, file_size_limit, django_service_ulr, task_logfile_name
from config.configuration import ip_data_path
from ipviewer.models import DetectedInformationPackage
from ipviewer.tasks import validate_and_detect_ips
from django.utils.translation import ugettext_lazy as _

logger = logging.getLogger(__name__)


def get_ip_overview_context():
    # TODO: read information about information package and representations from METS/EAD/DC
    total_size = "56MB"
    total_number_content_files = 16
    content_mime_types = ["text/pdf", "text/msword"]
    return {
        "object_id": "urn:uuid:d0bbd07c-74a0-4c0d-9bc8-37d503f705bd",
        "title": "testing.test.202007301809",
        "representations": [
            {
                "identifier": "word",
                "label": "MS Word",
                "description": "PDF representation (original submission)",
            },
            {
                "identifier": "pdf",
                "label": "PDF",
                "description": "PDF representation (migration on ingest)",
            },
            {
                "identifier": "pdfa",
                "label": "PDF/A",
                "description": "PDF/A representation (migration action)",
            }
        ],
        "stats": {
            "total_size": total_size,
            "total_number_content_files": total_number_content_files,
            "content_mime_types": ", ".join(content_mime_types),
        }
    }


@login_required
def ip_overview(request):
    template = loader.get_template('ipviewer/ip_overview.html')
    return HttpResponse(template.render(context=get_ip_overview_context(), request=request))


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
        # reset selection bevore the new selection is set
        DetectedInformationPackage.objects.all().update(selected=False)  # noqa
        context.update(get_ip_overview_context())
        # register selected ip
        ip = context['object']
        ip.selected = True
        ip.save()
        return context


@login_required
def ip_structure(request, tab):
    template = loader.get_template('ipviewer/ip_structure.html')
    # TODO: logical/physical view data
    logical_view_data = [
        {
            "text": "urn:uuid:46f99745-2f60-4849-9406-d3fe40f67a67",
            "icon": "fa fa-archive fa-fw",
            "nodes": [
                {
                    "text": "rep1",
                    "icon": "fa fa-inbox fa-fw",
                    "nodes": [
                        {
                            "icon": "fa fa-file-pdf-o fa-fw",
                            "text": "pdf-file-1"
                        },
                        {
                            "icon": "fa fa-file-pdf-o fa-fw",
                            "text": "pdf-file-2"
                        }
                    ]
                },
                {
                    "text": "rep2",
                    "icon": "fa fa-inbox fa-fw",
                    "nodes": [
                        {
                            "icon": "fa fa-file-word-o fa-fw",
                            "text": "ms-word-doc-1"
                        },
                        {
                            "icon": "fa fa-file-word-o fa-fw",
                            "text": "ms-word-doc-2"
                        }
                    ]
                },
            ]
        }
    ]
    physical_view_data = [
        {
            "text": "Container files",
            "icon": "fa fa-boxes fa-fw",
            "nodes": [
                {
                    "text": "ip.avd.001.v01.tar",
                    "icon": "fa fa-archive fa-fw",
                    "nodes": [
                        {
                            "icon": "fa fa-inbox fa-fw",
                            "text": "rep1",
                            "nodes": [
                                {
                                    "icon": "fa fa-file-pdf-o fa-fw",
                                    "text": "pdf-doc-1"
                                },
                                {
                                    "icon": "fa fa-file-pdf-o fa-fw",
                                    "text": "pdf-doc-2"
                                }
                            ]
                        }
                    ]
                },
                {
                    "text": "ip.avd.002.v01.tar",
                    "icon": "fa fa-archive fa-fw",
                    "nodes": [
                        {
                            "icon": "fa fa-inbox fa-fw",
                            "text": "rep2",
                            "nodes": [
                                {
                                    "icon": "fa fa-file-word-o fa-fw",
                                            "text": "ms-word-doc-1"
                                },
                                {
                                    "icon": "fa fa-file-word-o fa-fw",
                                            "text": "ms-word-doc-2"
                                }
                            ]
                        }
                    ]
                }

            ]
        }
    ]
    context = {
        "logical_view_data": logical_view_data,
        "physical_view_data": physical_view_data,
        "tab": tab
    }
    return HttpResponse(template.render(context=context, request=request))


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
    template = loader.get_template('ipviewer/representations.html')
    # TODO: read versions from PREMIS file
    inventory = {
        "versions": {
            "00000": {
                "created": "2021-03-07T20:51:30Z",
                "message": "Original SIP"
            },
            "00001": {
                "created": "2021-03-07T20:51:33Z",
                "message": "AIP (original ingest)"
            },
            "00002": {
                "created": "2021-03-08T13:48:58Z",
                "message": "AIP (original ingest)"
            },
            "00003": {
                "created": "2021-03-08T13:59:33Z",
                "message": "AIP (update)"
            }
        }
    }
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
        min_dt = get_date_from_iso_str(min_dtstr, DT_ISO_FORMAT)
        max_dt = get_date_from_iso_str(max_dtstr, DT_ISO_FORMAT)
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
        "tab": tab
    }
    return HttpResponse(template.render(context=context, request=request))


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


@csrf_exempt
def representation_dependency_graph(request):  # noqa
    # TODO: read migration paths from PREMIS file
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


class InformationPackageTable(tables.Table):
    information_package = tables.Column(orderable=False, verbose_name=_('Detected Information Package'))
    selected = tables.LinkColumn('ip_overview_select', kwargs={'pk': A('pk')}, verbose_name=_('Selection'), orderable=False)

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
