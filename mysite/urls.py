from django.contrib import admin
from django.urls import path,include
from blog import views


urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('blog.urls')),
    path('polls/', include('polls.urls')),
    
]
