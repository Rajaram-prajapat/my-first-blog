import logging
from django.core.paginator import Paginator
from datetime import datetime
from django.http import Http404
from django.shortcuts import render
from django.utils import timezone
from .models import Post, Category, Tag, Comment, Reply
from blog.models import CustomUser
from django.utils.timezone import now
from django.contrib.auth.models import User
from django.http import HttpResponse, HttpResponseRedirect, HttpResponseForbidden
from django.template import Template
from django.shortcuts import render, get_object_or_404
from .forms import PostForm, ProfileForm
from django.shortcuts import redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth import logout
from .forms import SignUpForm, LoginForm
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from .utils import send_email_to_all_users, send_email_to_user
from django.contrib import messages
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth import update_session_auth_hash
from django.core.exceptions import ValidationError
from .forms import CsvUploadForm
import csv
from io import StringIO

logger = logging.getLogger(__name__)

def post_list(request):
    posts = Post.objects.all()  # Start with all posts
    categories = Category.objects.all()  # Get all categories for filter
    tags = Tag.objects.all()  # Get all tags for filter

    # Category filter
    category_slug = request.GET.get('category')
    if category_slug:
        posts = posts.filter(category__slug=category_slug)  # Filter by category slug

    # Tag filter
    tag_slug = request.GET.get('tag')
    if tag_slug:
        posts = posts.filter(tags__slug=tag_slug)  # Filter by tag slug

    # Author filter
    author_username = request.GET.get('author')
    if author_username:
        posts = posts.filter(author__username=author_username)  # Filter by author username

    # Date filter
    date = request.GET.get('date')
    if date:
        try:
            # Ensure the date is in the correct format (YYYY-MM-DD)
            date_obj = datetime.strptime(date, "%Y-%m-%d").date()
            posts = posts.filter(published_date__date=date_obj)  # Filter by date
        except ValueError:
            # Invalid date format, handle it
            raise Http404("Invalid date format. Please use YYYY-MM-DD.")

    # Pagination
    paginator = Paginator(posts, 10)  # Show 10 posts per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'blog/post_list.html', {
        'posts': page_obj,
        'categories': categories,
        'tags': tags
    })

def posts_by_author(request, author_username):
    # Filter posts by the given author's username
    posts = Post.objects.filter(author__username=author_username)

    # Pagination
    paginator = Paginator(posts, 10)  # Show 10 posts per page
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    return render(request, 'blog/post_list.html', {
        'posts': page_obj,
        'author_username': author_username,  # Pass author for the template
    })

def signup(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # Log the user in after they sign up
            return redirect('blog:post_list')  # Use namespaced URL for post_list
    else:
        form = SignUpForm()
    return render(request, "blog/signup.html", {'form': form})

from django.contrib.auth import authenticate, login
from django.shortcuts import render, redirect
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')

            # Authenticate user
            user = authenticate(username=username, password=password)

            if user is not None:
                # Login user if authenticated successfully
                login(request, user)
                return redirect('blog:post_list')  # Or wherever you want to redirect after login
            else:
                # If authentication fails (incorrect username or password), show an error message
                messages.error(request, "Invalid username or password.")
        else:
            # If the form is invalid, show a form error
            messages.error(request, "Please fill in the required fields correctly.")

    else:
        form = AuthenticationForm()

    return render(request, 'blog/login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('blog:login') 


def post_detail(request, slug):
    # Fetch the post using the slug
    post = get_object_or_404(Post, slug=slug)
    
    # Get approved comments for this post
    comments = post.comments.filter(approved=True)
    
    # Handle comment submission
    if request.method == 'POST' and 'comment_text' in request.POST:
        text = request.POST['comment_text']
        comment = Comment(post=post, author=request.user, text=text)
        comment.save()
        # Redirect to the same post detail page after submitting a comment
        return HttpResponseRedirect(reverse('blog:post_detail', kwargs={'slug': post.slug}))

    # Handle reply submission
    if request.method == 'POST' and 'reply_text' in request.POST:
        if not request.user.is_authenticated:
            messages.error(request, 'You need to be logged in to reply to this comment.')
            return HttpResponseRedirect(reverse('blog:post_detail', kwargs={'slug': post.slug}))
        
        comment_id = request.POST['comment_id']
        comment = get_object_or_404(Comment, id=comment_id)
        text = request.POST['reply_text']
        
        reply = Reply(comment=comment, author=request.user, text=text)
        reply.save()
        
        # Redirect to the same post detail page after submitting a reply
        return HttpResponseRedirect(reverse('blog:post_detail', kwargs={'slug': post.slug}))
    # Render the post detail page with the post and comments
    return render(request, 'blog/post_detail.html', {'post': post, 'comments': comments})




from django.core.mail import send_mail
from django.conf import settings

# def send_test_email():
#     subject = 'Test Email from Django'
#     message = 'This is a test email sent from Django.'
#     from_email = settings.EMAIL_HOST_USER  # You can also hardcode the sender's email
#     recipient_list = ['recipient@example.com']  # List of recipients

#     send_mail(subject, message, from_email, recipient_list)

@login_required
def post_new(request, post_id=None):
    if post_id:  # Editing an existing post
        post = Post.objects.get(id=post_id)
        form = PostForm(request.POST or None, request.FILES or None, instance=post)
    else:  # Creating a new post
        post = None
        form = PostForm(request.POST or None, request.FILES or None)

    if request.method == "POST":
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user  # Set the author to the logged-in user
            post.published_date = timezone.now()
            post.save()
            

            # Many-to-many field like tags need to be saved separately
            form.save_m2m()  # Save the many-to-many fields (tags) after saving the post

            # try:
            #     send_email_to_all_users(post)  # Send email notifications after the post is saved
            #     messages.success(request, "Post created/updated successfully and email notifications sent!")
            # except Exception as e:
            #     messages.error(request, f"Post created/updated, but email notifications failed: {str(e)}")
            #     logger.error(f"Failed to send email notifications for post {post.slug}: {str(e)}")

            if post_id:
                return redirect('blog:post_detail', slug=post.slug)  # Redirect to post detail if editing
            return redirect('blog:post_list')  # Redirect to the post list after creating a new post

    else:
        # If it's a GET request, render the form
        form = PostForm(instance=post)

    return render(request, 'blog/post_edit.html', {'form': form})

@login_required
def post_edit(request, slug):
    post = get_object_or_404(Post, slug=slug)

    if post.author != request.user:
        # If the user is not the author, return a 403 Forbidden response
        return HttpResponseForbidden("You are not authorized to edit this post.")

    
    if request.method == "POST":
        form = PostForm(request.POST, request.FILES, instance=post)
        if form.is_valid():
            post = form.save(commit=False)
            post.author = request.user
            post.published_date = timezone.now()
            # send_email_to_all_users(post)
            post.save()
            form.save_m2m()

            # Try to send email notifications to all users
            # try:
            #     send_email_to_all_users(post)  # Sending notifications to all registered users
            #     messages.success(request, "Post updated successfully and email notifications sent!")
            # except Exception as e:
            #     # Handle any email failures
            #     messages.error(request, f"Post updated, but email notifications failed: {str(e)}")
            #     # Optionally, log the error for debugging purposes
            #     logger.error(f"Failed to send email notifications for post {post.slug}: {str(e)}")

            return redirect('blog:post_detail', slug=post.slug)  # Redirect to post detail page
    
    else:
        form = PostForm(instance=post)

    return render(request, 'blog/post_edit.html', {'form': form, 'post': post})


def send_email(request, slug):
    post = get_object_or_404(Post, slug=slug)
    # try:
    #     send_email_to_user(post)  # Send email to a single user
    #     messages.success(request, "Email sent successfully!")
    # except Exception as e:
    #     # Handle any failures in sending the email
    #     messages.error(request, f"Failed to send email: {str(e)}")
    #     # Optionally, log the error for debugging purposes
    #     logger.error(f"Failed to send email for post {post.slug}: {str(e)}")
    return redirect('blog:post_detail', slug=post.slug)

@login_required
def profile(request, username):
    user = request.user  # Get the logged-in user

    # Handle Profile Form Submission
    if request.method == 'POST':
        # Handling Profile Update
        form = ProfileForm(request.POST, request.FILES, instance=user)
        
        # Handle Password Change Form
        password_change_form = PasswordChangeForm(user, request.POST)
        
        # Check if a password change is being made
        if 'current_password' in request.POST:
            if password_change_form.is_valid():
                user.set_password(password_change_form.cleaned_data['new_password'])
                user.save()
                update_session_auth_hash(request, user)  # Keeps the user logged in after password change
                messages.success(request, "Your password has been updated successfully!")
                return redirect('blog:profile', username=user.username)
            else:
                messages.error(request, "There was an error with your password change.")
        
        # Handle Profile Form Submission
        elif form.is_valid():
            form.save()
            messages.success(request, "Your profile has been updated successfully!")
            return redirect('blog:profile', username=user.username)
        
    else:
        # Create instances of both forms (ProfileForm and PasswordChangeForm)
        form = ProfileForm(instance=user)
        password_change_form = PasswordChangeForm(user)

    return render(request, 'blog/profile.html', {
        'form': form,
        'password_change_form': password_change_form
    })



def tag_detail(request, slug):
    # Fetch the tag using the slug
    tag = get_object_or_404(Tag, slug=slug)
    
    # Retrieve posts associated with this tag (optional)
    posts = tag.posts.all()
    
    return render(request, 'blog/post_list.html', {'tag': tag, 'posts': posts})

def category_detail(request, slug):
    # Fetch the category by its slug
    category = get_object_or_404(Category, slug=slug)
    
    # Retrieve posts associated with this category
    posts = category.posts.all()  # Use 'posts' if that's the correct related name
    
    return render(request, 'blog/post_list.html', {'category': category, 'posts': posts})

def upload_csv_view(request):
    message = None

    if request.method == 'POST':
        form = CsvUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['csv_file']
                if not csv_file.name.endswith('.csv'):
                    raise ValidationError("Only CSV files are allowed.")
                
                # Read and process the CSV data
                csv_data = csv_file.read().decode('utf-8')
                csv_reader = csv.reader(StringIO(csv_data))
                
                # Process the CSV based on the selected model (CustomUser or Post)
                headers = next(csv_reader)
                if 'Email' in headers:  # If the CSV is for CustomUser
                    for row in csv_reader:
                        email, first_name, last_name = row
                        CustomUser.objects.create(email=email, first_name=first_name, last_name=last_name)
                    message = "CSV Imported Successfully!"
                elif 'Title' in headers:  # If the CSV is for Post
                    for row in csv_reader:
                        title, author, created_date = row
                        author_obj = CustomUser.objects.get(email=author)
                        Post.objects.create(title=title, author=author_obj, created_date=created_date)
                    message = "Posts CSV Imported Successfully!"
                else:
                    message = "Invalid CSV format."

            except ValidationError as e:
                message = str(e)

    else:
        form = CsvUploadForm()

    return render(request, 'blog/upload_csv.html', {'form': form, 'message': message})

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.pagination import PageNumberPagination
from rest_framework.exceptions import ValidationError

from django.contrib.auth import authenticate
from django.contrib.auth.forms import UserCreationForm
from blog.models import CustomUser
from blog.serializer import CustomUserSerializer, SignUpSerializer, LoginSerializer

from rest_framework.authtoken.models import Token


class CustomPagination(PageNumberPagination):
    page_size = 10  # Set the page size (number of items per page)
    page_size_query_param = 'page_size'  # Allow clients to customize the page size
    max_page_size = 100  # Limit the maximum page size to 100


class UserApi(APIView):
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return CustomUser.objects.all()  # You can add filtering here

    def get(self, request):
        try:
            users = self.get_queryset()  # Get the users
            paginator = CustomPagination()
            result_page = paginator.paginate_queryset(users, request)
            serializer = CustomUserSerializer(result_page, many=True)
            return paginator.get_paginated_response(serializer.data)
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Error occurred while fetching users: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SignupApi(APIView):
    permission_classes = [AllowAny]  # Allow anyone to access the signup API

    def post(self, request):
        try:
            # Log incoming request data for debugging (use logger in production)
            logger.debug(f"Request Data: {request.data}")  # Replace print with logger

            # Use the custom SignUpSerializer
            serializer = SignUpSerializer(data=request.data)

            if serializer.is_valid():
                # Save the user and generate a token
                user = serializer.save()

                # Create or get the token for the user (Token-based authentication)
                token, created = Token.objects.get_or_create(user=user)

                # Return the token in the response
                return Response({
                    'status': 'success',
                    'data': {
                        'token': token.key,
                        'username': user.username,
                        'email': user.email,
                    }
                }, status=status.HTTP_201_CREATED)

            # If validation fails, return a custom error response with only the message
            logger.warning(f"Serializer Errors: {serializer.errors}")  # Use logger

            # Combine all error messages into a single message
            error_messages = " ".join([f"{key}: {value[0]}" for key, value in serializer.errors.items()])

            return Response({
                'status': 'error',
                'message': error_messages
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Log the full error message for debugging
            logger.error(f"Error during signup: {str(e)}")  # Use logger
            return Response({
                'status': 'error',
                'message': f'Error occurred during signup: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginApi(APIView):
    permission_classes = [AllowAny]  # Allow anyone to access the login API

    def post(self, request):
        try:
            # Use the LoginSerializer to validate the request data
            serializer = LoginSerializer(data=request.data)

            if serializer.is_valid():
                # If the credentials are valid, get the user
                user = serializer.validated_data['user']

                # Create or retrieve the token for the user
                token, created = Token.objects.get_or_create(user=user)

                # Return the token in the response
                return Response({
                    'status': 'success',
                    'data': {
                        'token': token.key,
                        'username': user.username,
                        'email': user.email,
                    }
                }, status=status.HTTP_200_OK)

            # Handle errors from serializer validation
            error_message = None

            # Check if the username is invalid
            if 'username' in serializer.errors:
                error_message = "Invalid username."

            # Check if the password is incorrect (typically handled by authenticate)
            elif 'password' in serializer.errors:
                error_message = "Incorrect password."

            # If both username and password errors are found
            elif 'non_field_errors' in serializer.errors:
                error_message = "Invalid username and/or incorrect password."

            # Default case if we didn't capture any specific errors
            if not error_message:
                error_message = "Invalid credentials."

            return Response({
                'status': 'error',
                'message': error_message
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Log any errors and return a 500 response
            logger.error(f"Error during login: {str(e)}")  # Use logger
            return Response({
                'status': 'error',
                'message': f'Error occurred during login: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)