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
    

    slug = AutoSlugField(populate_from='title', unique=True)

    featured_image = models.ImageField(upload_to='featured_images/', blank=True, null=True)
    thumbnail_image = models.ImageField(upload_to='thumbnail_images/', blank=True, null=True)

    def save(self, *args, **kwargs):
        # Only check for existing posts if it's an update (i.e., self.id is not None)
        if self.id:
            try:
                existing_post = self.__class__.objects.get(id=self.id)
                if self.title != existing_post.title:  # Check if the title has changed
                    self.slug = slugify(self.title)  # Regenerate the slug if the title changes
            except self.__class__.DoesNotExist:
                # If the post doesn't exist (which should never happen here)
                self.slug = slugify(self.title)
        else:
            # For new posts, just generate the slug based on the title
            self.slug = slugify(self.title)

        # Call the superclass save method to actually save the object
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
    profile_picture = models.ImageField(upload_to='profile_pictures/', blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.username:
            self.username = self.email  # Set username to email if not provided
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username