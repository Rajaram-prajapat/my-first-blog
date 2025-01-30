from django.urls import path
from . import views

urlpatterns = [
    path('', views.post_list, name='post_list'),
    # path('admin/', admin.site.urls),
    # path('blog/', include('blog.urls'))
]
