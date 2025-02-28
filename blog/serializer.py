from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from .models import Post
from rest_framework.exceptions import ValidationError
from django.utils.text import slugify   
from .models import Post, Tag, Category, Comment, Reply

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()  # CustomUser model
        fields = ['id', 'username', 'first_name', 'last_name', 'email', 'date_joined', 'profile_picture']
        read_only_fields = ['id', 'username', 'email', 'date_joined']  

    def update(self, instance, validated_data):
        # Update the profile fields
        instance.first_name = validated_data.get('first_name', instance.first_name)
        instance.last_name = validated_data.get('last_name', instance.last_name)

        # Handle the profile photo
        if 'profile_picture' in validated_data:
            instance.profile_picture = validated_data.get('profile_picture')

        instance.save()
        return instance

class SignUpSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = get_user_model()  # Dynamically get the user model
        fields = ['username', 'email', 'password1', 'password2']

    def validate(self, data):
        # Check if password2 is missing
        if 'password2' not in data:
            raise serializers.ValidationError("Please confirm your password.")
        
        # Check if password1 and password2 match
        if data['password1'] != data['password2']:
            raise serializers.ValidationError("Password and confirm password do not match.")
        
        return data

    def create(self, validated_data):
        # Remove password2 as it's not needed for user creation
        validated_data.pop('password2')

        # Create a new user instance and set password using create_user (hashes password)
        user = get_user_model().objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password1']
        )
        return user
    
    def validate_email(self, email):
        if get_user_model().objects.filter(email=email).exists():
            raise serializers.ValidationError("A user with that email already exists.")
        return email

# Login Serializer
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    class Meta:
        model = get_user_model()
        fields = ['username', 'password']

class PostSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()
    tags = serializers.PrimaryKeyRelatedField(queryset=Tag.objects.all(), many=True)
    category = serializers.PrimaryKeyRelatedField(queryset=Category.objects.all())

    class Meta:
        model = Post
        fields = ['id', 'title', 'text', 'author', 'created_date', 'published_date', 'category', 'tags', 'slug', 'featured_image', 'thumbnail_image']
        read_only_fields = ['author']

    def get_author(self, obj):
        # Assuming 'obj.author' is a user object
        return obj.author.username

    def create(self, validated_data):
        # Automatically set the author to the logged-in user
        user = self.context.get('request').user if 'request' in self.context else None
        if not user:
            raise serializers.ValidationError("User must be authenticated to create a post.")
        
        validated_data['author'] = user  # Automatically set the logged-in user as the author

        # Ensure slug is generated if not provided
        title = validated_data.get('title', '')
        slug = validated_data.get('slug', None)
        if not slug and title:
            validated_data['slug'] = slugify(title)

        return super().create(validated_data)
    
    def update(self, instance, validated_data):
        # Prevent changing the author field during updates
        if 'author' in validated_data:
            raise serializers.ValidationError("You cannot change the author of an existing post.")
        
        # Ensure slug is updated if title changes
        if 'title' in validated_data:
            instance.slug = slugify(validated_data['title'])

        return super().update(instance, validated_data)
    
class Replyserializer(serializers.ModelSerializer):
    # Assuming Reply has at least 'author' and 'text' fields
    class Meta:
        model = Reply
        fields = ['id', 'author', 'text', 'created_date']

class Commentserializer(serializers.ModelSerializer):
    author = serializers.StringRelatedField()  # Display the username of the author
    replies = Replyserializer(many=True, read_only=True)

    class Meta:
        model = Comment
        fields = ['id', 'author', 'text', 'created_date', 'replies']

    def create(self, validated_data):
        # Ensure the logged-in user is associated with the comment
        user = self.context.get('request').user if 'request' in self.context else None
        if user:
            validated_data['author'] = user  # Associate logged-in user as the author
        else:
            raise serializers.ValidationError("User must be authenticated to comment.")

        # Optionally set 'approved' to False by default
        validated_data['approved'] = False

        # Call the parent create method to create and save the comment
        return super().create(validated_data)


class Postwithcommentserializer(serializers.ModelSerializer):
    comments = Commentserializer(many=True, read_only=True)

    class Meta:
        model = Post
        fields= ['id', 'title', 'text', 'comments']