from django.contrib.auth import get_user_model
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User
from .models import Post

User = get_user_model()

def send_email_to_all_users(post: Post):
    """ Sends an email notification to all registered users about a new or updated post. """
    users = User.objects.all()  # Use the custom user model

    subject = f"New post: {post.title}"
    # Use a static URL or any other logic to create the URL
    message = f"Check out the new post: http://127.0.0.1:8000/post/{post.slug}/"
    
    # Send an email to each user
    for user in users:
        send_mail(subject, message, 'rajant0254@gmail.com', [user.email])


def send_email_to_user(post: Post):
    """ Sends an email notification to a specific user about a post. """
    user = post.author  # Assuming the email is sent to the post's author
    subject = f"Update on your post: {post.title}"
    message = f"Your post has been updated. Check it out here: {post.get_absolute_url()}"
    
    send_mail(subject, message, 'rajant0254@gmail.com', [user.email])