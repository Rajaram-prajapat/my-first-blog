import csv
from io import StringIO
from django import forms
from .forms import PostForm, CsvUploadForm
from django.shortcuts import render
from django.http import HttpResponse
from django.contrib import admin
from .models import Post, Category, Tag, Comment, Reply
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser
from django.utils.text import slugify
from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
from datetime import datetime

def export_as_csv(modeladmin, request, queryset):
    """Export selected rows as CSV."""
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{modeladmin.model.__name__}_export.csv"'
    writer = csv.writer(response)

    # Export users if the model is CustomUser
    if modeladmin.model == CustomUser:
        writer.writerow(['Email', 'First Name', 'Last Name', 'Is Staff', 'Is Active', 'Username', 'Password'])
        for obj in queryset:
            writer.writerow([obj.email, obj.first_name, obj.last_name, obj.is_staff, obj.is_active, obj.username, obj.password])

    return response

def import_csv(modeladmin, request, queryset=None):
    """Import users from a CSV file."""
    if 'csv_file' not in request.FILES:
        raise ValidationError("No CSV file provided.")
    
    csv_file = request.FILES['csv_file']
    if not csv_file.name.endswith('.csv'):
        raise ValidationError("Only CSV files are allowed.")

    # Read CSV content
    csv_data = csv_file.read().decode('utf-8')
    csv_reader = csv.reader(StringIO(csv_data))

    if modeladmin.model == CustomUser:
        headers = next(csv_reader)  # Read header row

        required_headers = ['Email', 'First Name', 'Last Name', 'Is Staff', 'Is Active', 'Username', 'Password']
        missing_headers = [header for header in required_headers if header not in headers]
        if missing_headers:
            raise ValidationError(f"Missing required headers: {', '.join(missing_headers)}")

        for row in csv_reader:
            email, first_name, last_name, is_staff, is_active, username, password = row
            is_staff = is_staff.lower() == 'true'
            is_active = is_active.lower() == 'true'

            try:
                user = CustomUser.objects.get(username=username)
                user.email = email
                user.first_name = first_name
                user.last_name = last_name
                user.is_staff = is_staff
                user.is_active = is_active
                user.save()
            except CustomUser.DoesNotExist:
                user = CustomUser.objects.create(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    is_staff=is_staff,
                    is_active=is_active,
                    password=make_password(password)  # Hash password before saving
                )
                user.save()

    return HttpResponse("CSV Import Successful", content_type="text/plain")

# CustomAdmin for Post and CustomUser
class PostAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'category', 'published_date', 'slug')
    list_filter = ('category', 'tags', 'published_date')
    search_fields = ['title', 'author__username', 'category__name', 'tags__name']
    exclude = ('slug',)  # Prevent manual editing of the slug field
    filter_horizontal = ['tags']
    actions = [export_as_csv]  # Export action for Post model


# Admin view for CustomUser
class CustomUserAdmin(admin.ModelAdmin):
    model = CustomUser
    list_display = ('email', 'first_name', 'last_name', 'is_staff', 'is_active')
    search_fields = ['email', 'first_name', 'last_name']
    actions = [export_as_csv]  # CSV export action

    def changelist_view(self, request, extra_context=None):
        """Override changelist to add CSV import form."""
        form = CsvUploadForm()
        
        if 'csv_upload' in request.POST:
            form = CsvUploadForm(request.POST, request.FILES)
            if form.is_valid():
                try:
                    import_csv(self, request)
                    self.message_user(request, "CSV import successful.")
                except ValidationError as e:
                    self.message_user(request, f"Error in CSV import: {e.message}")

        extra_context = extra_context or {}
        extra_context.update({
            'form': form,
            'enctype': 'multipart/form-data',  # Ensure form can handle file uploads
        })

        return super().changelist_view(request, extra_context=extra_context)


class CategoryAdmin(admin.ModelAdmin):
    search_fields = ['name']  # Enables search functionality for category name
    actions = [export_as_csv]

class TagAdmin(admin.ModelAdmin):
    search_fields = ['name']
    actions = [export_as_csv]

class CommentAdmin(admin.ModelAdmin):
    search_fields=['author__username']
    actions = [export_as_csv]

class ReplyAdmin(admin.ModelAdmin):
    search_fields=['author__username']
    actions = [export_as_csv]

admin.site.register(Post, PostAdmin)
admin.site.register(Category, CategoryAdmin)
admin.site.register(Tag, TagAdmin)
admin.site.register(Comment, CommentAdmin)
admin.site.register(Reply, ReplyAdmin)
admin.site.register(CustomUser, CustomUserAdmin)