from django.db.models.signals import pre_save
from django.dispatch import receiver
from .models import Post
from django.utils.text import slugify

@receiver(pre_save, sender=Post)
def update_slug_on_title_change(sender, instance, **kwargs):
    if instance.pk:  # Check if the post already exists
        old_post = Post.objects.get(pk=instance.pk)
        if old_post.title != instance.title:  # If title has changed
            base_slug = slugify(instance.title)
            slug = base_slug
            counter = 1
            while Post.objects.filter(slug=slug).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
            instance.slug = slug
    else:
        base_slug = slugify(instance.title)
        slug = base_slug
        counter = 1
        while Post.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{counter}"
            counter += 1
        instance.slug = slug