# # from django.contrib import admin
# from django.urls import path
# from . import views

# urlpatterns = [
#     path('', views.post_list, name='post_list'),
# ]
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

from django.conf import settings
from django.conf.urls.static import static

app_name = 'blog'

urlpatterns = [
    path('profile/<str:username>/', views.profile, name='profile'),
    path('', views.post_list, name='post_list'),  # Make sure this is named 'post_list'
    path('signup/', views.signup, name='signup'),  # Ensure signup view has a name
    path('login/', views.login_view, name='login'),  # Ensure login view has a name
    path('logout/', views.logout_view, name='logout'),
    path('post/', views.post_list, name='post_list'),
    path('post/edit/<slug:slug>/', views.post_edit, name='post_edit'),
    path('post/new/', views.post_new, name='post_new'),
    path('login/', auth_views.LoginView.as_view(), name='login'),
    path('post/<slug:slug>/', views.post_detail, name='post_detail'),
    path('category/<slug:slug>/', views.category_detail, name='category_detail'),
    path('tag/<slug:slug>/', views.tag_detail, name='tag_detail'),
    path('author/<str:author_username>/', views.posts_by_author, name='author_filter'), 
    path('upload-csv/', views.upload_csv_view, name='upload_csv'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)