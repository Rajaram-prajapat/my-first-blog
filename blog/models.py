from django.db import models
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import AbstractUser ,AbstractBaseUser, BaseUserManager, PermissionsMixin
from autoslug import AutoSlugField
from django.utils.text import slugify

class Category(models.Model):
    name = models.CharField(max_length=100)
    slug = AutoSlugField(populate_from='name', unique=True)

    def __str__(self):
        return self.name

class Tag(models.Model):
    name = models.CharField(max_length=100, unique=True)
    slug = AutoSlugField(populate_from='name', unique=True)  # Slug field

    def __str__(self):
        return self.name
    
class Post(models.Model):
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    title = models.CharField(max_length=200)
    text = models.TextField()
    created_date = models.DateTimeField(default=timezone.now)
    published_date = models.DateTimeField(blank=True, null=True)
    category = models.ForeignKey(Category, on_delete=models.SET_NULL, null=True, blank=True)
    tags = models.ManyToManyField(Tag, related_name='posts', blank=True)

    # AutoSlugField to generate unique slugs based on title
    slug = AutoSlugField(populate_from='title', unique=True)

    # Featured Image for the Post
    featured_image = models.ImageField(upload_to='featured_images/', blank=True, null=True)

    # Thumbnail Image for the Post
    thumbnail_image = models.ImageField(upload_to='thumbnail_images/', blank=True, null=True)

    def save(self, *args, **kwargs):
        # Check if the title has changed
        if not self.slug or self.title != self.__class__.objects.get(id=self.id).title:
            self.slug = slugify(self.title)  # Re-generate slug based on the new title

        super(Post, self).save(*args, **kwargs)

    def publish(self):
        self.published_date = timezone.now()
        self.save()

    def __str__(self):
        return self.title

class Comment(models.Model):
    post = models.ForeignKey(Post, on_delete=models.CASCADE, related_name='comments')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    text = models.TextField()
    created_date = models.DateTimeField(default=timezone.now)
    approved = models.BooleanField(default=False)

    def approve(self):
        self.approved = True
        self.save()

    def __str__(self):
        return f"Comment by {self.author} on {self.post}"

# Reply model (Self-Referential relation for replies to comments)
class Reply(models.Model):
    comment = models.ForeignKey(Comment, on_delete=models.CASCADE, related_name='replies')
    author = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    text = models.TextField()
    created_date = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"Reply by {self.author} on {self.comment}"
    
# class CustomUserManager(BaseUserManager):
#     def create_user(self, email, password=None, **extra_fields):
#         if not email:
#             raise ValueError('The Email field must be set')
#         email = self.normalize_email(email)
#         user = self.model(email=email, **extra_fields)
#         user.set_password(password)
#         user.save(using=self._db)
#         return user


#     def create_superuser(self, email, password=None, **extra_fields):
#         """Create and return a superuser."""
#         extra_fields.setdefault('is_staff', True)
#         extra_fields.setdefault('is_active', True)
#         return self.create_user(email, password, **extra_fields)


# class CustomUser(AbstractUser):
#     """Custom User model with email as the unique identifier."""
    
#     email = models.EmailField(unique=True)
#     bio = models.TextField(blank=True, null=True)
#     profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)
    
#     objects = CustomUserManager()

#     def __str__(self):
#         return self.email
# Create your models here.

class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)

        # Ensure the username is unique
        if CustomUser.objects.filter(username=user.username).exists():
            raise ValueError(f"The username {user.username} is already taken.")
        
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_active', True)
        return self.create_user(email, password, **extra_fields)
    
class CustomUser(AbstractUser):
    objects = CustomUserManager()
    # You can add additional fields to the user here if needed
    bio = models.TextField(blank=True, null=True)
    # profile_picture = models.ImageField(upload_to='', null=True, blank=True)
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email  # Set username to email if not provided
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username
    
# from rest_framework.authtoken.models import Token
# try:
#     user = CustomUser.objects.create_user(email=None)
#     token = Token.objects.create(user=user)
#     print(token.key)  # Print the generated token key
# except ValueError as e:
#     print(f"Error: {e}")