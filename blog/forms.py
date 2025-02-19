from django import forms
from .models import Post ,CustomUser
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User


class SignUpForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Enter a username'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Enter your email'}),
            'password1': forms.PasswordInput(attrs={'placeholder': 'Enter your password'}),
            'password2': forms.PasswordInput(attrs={'placeholder': 'Confirm your password'}),
        }

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise forms.ValidationError("A user with that email already exists.")
        return email

    def clean_password1(self):
        password = self.cleaned_data.get('password1')
        if len(password) < 8:
            raise forms.ValidationError("Your password must contain at least 8 characters.")
        if not any(char.isdigit() for char in password):
            raise forms.ValidationError("Your password must contain at least one number.")
        if not any(char.isalpha() for char in password):
            raise forms.ValidationError("Your password must contain at least one letter.")
        return password

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')

        # Check if passwords match
        if password1 != password2:
            raise forms.ValidationError("Please enter the same password in both fields.")  # Custom error message
        return password2

    # Custom error messages for password fields
    error_messages = {
        'password1': {
            'required': "Please enter a password.",
            'min_length': "Your password is too short. It must contain at least 8 characters.",
        },
        'password2': {
            'required': "Please confirm your password.",
        },
    }

class LoginForm(AuthenticationForm):
    class Meta:
        model = User
        fields = ['username', 'password']

class PostForm(forms.ModelForm):
    class Meta:
        model = Post
        fields = ['title', 'text', 'category', 'tags', 'featured_image', 'thumbnail_image']

    featured_image = forms.ImageField(required=False)
    thumbnail_image = forms.ImageField(required=False)

class ProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'first_name', 'last_name', 'profile_picture'] 

class CustomUserCreationForm(UserCreationForm):
    # Add additional fields for user registration (e.g., bio, profile picture)
    bio = forms.CharField(widget=forms.Textarea, required=False)
    profile_picture = forms.ImageField(required=False)

    class Meta:
        model = CustomUser
        fields = ('username', 'bio', 'profile_picture', 'password1', 'password2')

class CsvUploadForm(forms.Form):
    csv_file = forms.FileField(label='Select a CSV file')
        