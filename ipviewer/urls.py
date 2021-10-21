"""ipviewer URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf.urls import url
from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

from config.configuration import log_current_configuration
from ipviewer.views import input_data, ip_structure, representations, upload, user_dir_files, \
    user_file_resource, validate_load_result, ip_overview, representation_dependency_graph, reload_table, \
    InformationPackageDetail, file_from_ip, get_basic_metadata
from ipviewer.views import ActivateLanguageView

urlptns = [
    url(r'^language/activate/(?P<language_code>[DE|de|EN|en]{2,2})/?', ActivateLanguageView.as_view(),
        name='activate_language'),
    url(r'^$', ip_overview, name='none'),
    url(r'^ip_overview$', ip_overview, name='ip_overview'),
    url(r'^ip_overview_select/(?P<pk>\d+)/$', InformationPackageDetail.as_view(), name='ip_overview_select'),
    url(r'^input_data/(?P<tab>\d+)$', input_data, name='input_data'),
    url(r'^validate-load-result$', validate_load_result, name='validate_load_result'),
    url(r'^reload-table$', reload_table, name='reload_table'),
    url(r'^ip_structure/(?P<tab>\d+)$', ip_structure, name='ip_structure'),
    url(r'^representations/(?P<tab>\d+)$', representations, name='representations'),
    url(r'^rep-dep-graph$', representation_dependency_graph, name='representation_dependency_graph'),
    url(r'^upload$', upload, name='upload'),
    url(r'^user-dir-files$', user_dir_files, name='user_dir_files'),
    url(r'^file-resource/(?P<file_path>.*)/$', user_file_resource, name='file_resource'),
    url(r'^file-from-ip/(?P<file_path>.+)/$', file_from_ip, name='file_from_ip'),
    url(r'^get-basic-metadata/(?P<file_path>.+)/$', get_basic_metadata, name='get_basic_metadata'),


    path('accounts/', include('django.contrib.auth.urls')),
    url(r'^admin', admin.site.urls),
]

urlpatterns = [
    url(r'^$', RedirectView.as_view(url='ipviewer/')),
    url(r'^ipviewer/', include(urlptns)),
]



# print configuration parameters at application startup
log_current_configuration()