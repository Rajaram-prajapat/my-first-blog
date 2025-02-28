from django.urls import path, include
from . import views 
from django.contrib.auth import views as auth_views
from django.contrib.auth.models import User
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import get_user_model 
from blog.views import LoginApi, SignupApi, ProfileApi, PostCreateAPIView, PostEditAPIView, CommentCreateAPIView, ReplyCreateAPIView, PostAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from rest_framework import routers, serializers, viewsets

User = get_user_model()

# Serializers define the API representation.
class UserSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = User
        fields = ['url', 'username', 'email', 'is_staff']

# ViewSets define the view behavior.
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()  # Make sure User model is correctly imported
    serializer_class = UserSerializer

# Routers provide an easy way of automatically determining the URL conf.
router = routers.DefaultRouter()
router.register(r'users', UserViewSet)

app_name = 'blog'

urlpatterns = [
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('profile/<str:username>/', views.profile, name='profile'),
    path('', views.post_list, name='post_list'),
    path('signup/', views.signup, name='signup'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('post/edit/<slug:slug>/', views.post_edit, name='post_edit'),
    path('post/new/', views.post_new, name='post_new'),
    path('post/<slug:slug>/', views.post_detail, name='post_detail'),
    path('category/<slug:slug>/', views.category_detail, name='category_detail'),
    path('tag/<slug:slug>/', views.tag_detail, name='tag_detail'),
    path('author/<str:author_username>/', views.posts_by_author, name='author_filter'), 
    path('upload-csv/', views.upload_csv_view, name='upload_csv'),
    path('loginapi/', LoginApi.as_view()),
    path('signupapi/', SignupApi.as_view()),
    path('profileapi/', ProfileApi.as_view(),name='profile_see'),
    path('profileapi/<str:username>/', ProfileApi.as_view(),name='profile_see'),
    path('api-auth/', include('rest_framework.urls')),
    path('postlist/', PostAPIView.as_view(), name='post-list'),
    path('posts/', PostCreateAPIView.as_view(), name='post_create'),
    path('posts/<slug:slug>/edit/', PostEditAPIView.as_view(), name='post_update'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('post/<int:post_id>/comment/', CommentCreateAPIView.as_view(), name='create_comment'),
    path('comment/<int:comment_id>/reply/', ReplyCreateAPIView.as_view(), name='create_reply'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + router.urls

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)