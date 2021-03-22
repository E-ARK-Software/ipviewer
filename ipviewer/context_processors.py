import json
import string

from django.contrib.auth.models import User
from django.utils import translation
from ipviewer.models import DetectedInformationPackage

import logging

from config.configuration import sw_version, sw_version_date, app_label, logo

logger = logging.getLogger(__name__)


def environment_variables(request):
    lang = request.META['HTTP_ACCEPT_LANGUAGE'][0:2] if 'HTTP_ACCEPT_LANGUAGE' in request.META else "en"
    if translation.LANGUAGE_SESSION_KEY in request.session:
        lang = request.session[translation.LANGUAGE_SESSION_KEY]

    u = User.objects.get(id=request.user.id)
    ips = DetectedInformationPackage.objects.filter(user=u, selected=True)  # noqa
    selected_ip = ips[0] if len(ips) > 0 else None

    return {
        'logo': logo,
        'sw_version': sw_version,
        'sw_version_date': sw_version_date,
        'app_label': app_label,
        'selected_ip': selected_ip
    }
