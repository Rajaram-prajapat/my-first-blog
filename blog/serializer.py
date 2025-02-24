from rest_framework import serializers
from .models import CustomUser
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate

class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser  
        fields = '__all__'  

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

        
class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        # Authenticate the user
        user = authenticate(username=username, password=password)

        if user is None:
            raise serializers.ValidationError("Invalid username or password.")

        # Return the user if authentication is successful
        data['user'] = user
        return data