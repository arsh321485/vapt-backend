# from django.contrib import admin
# from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
# from django.contrib.auth.forms import ReadOnlyPasswordHashField
# from django import forms
# from .models import User


# class UserCreationForm(forms.ModelForm):
#     """A form for creating new users. Includes all the required
#     fields, plus a repeated password."""
#     password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
#     password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)

#     class Meta:
#         model = User
#         fields = ('email', 'firstname', 'lastname', 'organisation_name', 'organisation_url')

#     def clean_password2(self):
#         # Check that the two password entries match
#         password1 = self.cleaned_data.get("password1")
#         password2 = self.cleaned_data.get("password2")
#         if password1 and password2 and password1 != password2:
#             raise forms.ValidationError("Passwords don't match")
#         return password2

#     def save(self, commit=True):
#         # Save the provided password in hashed format
#         user = super().save(commit=False)
#         user.set_password(self.cleaned_data["password1"])
#         if commit:
#             user.save()
#         return user


# class UserChangeForm(forms.ModelForm):
#     """A form for updating users. Includes all the fields on
#     the user, but replaces the password field with admin's
#     password hash display field.
#     """
#     password = ReadOnlyPasswordHashField()

#     class Meta:
#         model = User
#         fields = (
#             'email', 'password', 'firstname', 'lastname', 
#             'organisation_name', 'organisation_url', 
#             'is_active', 'is_staff', 'is_superuser'
#         )

#     def clean_password(self):
#         # Regardless of what the user provides, return the initial value.
#         # This is done here, rather than on the field, because the
#         # field does not have access to the initial value
#         return self.initial["password"]


# @admin.register(User)
# class UserAdmin(BaseUserAdmin):
#     # The forms to add and change user instances
#     form = UserChangeForm
#     add_form = UserCreationForm

#     # The fields to be used in displaying the User model.
#     list_display = (
#         'email', 'firstname', 'lastname', 'organisation_name', 
#         'is_staff', 'is_active', 'created_at'
#     )
#     list_filter = ('is_staff', 'is_superuser', 'is_active', 'created_at')
    
#     fieldsets = (
#         (None, {'fields': ('email', 'password')}),
#         ('Personal info', {
#             'fields': (
#                 'firstname', 'lastname', 'organisation_name', 'organisation_url'
#             )
#         }),
#         ('Permissions', {
#             'fields': (
#                 'is_active', 'is_staff', 'is_superuser', 
#                 'groups', 'user_permissions'
#             )
#         }),
#         ('Important dates', {'fields': ('last_login', 'created_at', 'updated_at')}),
#     )
    
#     # add_fieldsets is not a standard ModelAdmin attribute. UserAdmin
#     # overrides get_fieldsets to use this attribute when creating a user.
#     add_fieldsets = (
#         (None, {
#             'classes': ('wide',),
#             'fields': (
#                 'email', 'firstname', 'lastname', 'organisation_name', 
#                 'organisation_url', 'password1', 'password2'
#             ),
#         }),
#     )
    
#     search_fields = ('email', 'firstname', 'lastname', 'organisation_name')
#     ordering = ('email',)
#     filter_horizontal = ('groups', 'user_permissions')
#     readonly_fields = ('created_at', 'updated_at')

#     def get_readonly_fields(self, request, obj=None):
#         if obj:  # editing an existing object
#             return self.readonly_fields + ('created_at', 'updated_at')
#         return self.readonly_fields


from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from django import forms
from .models import User


# =========================
# User Creation Form
# =========================
class UserCreationForm(forms.ModelForm):
    """Form for creating new users in admin"""
    password1 = forms.CharField(label="Password", widget=forms.PasswordInput)
    password2 = forms.CharField(label="Password confirmation", widget=forms.PasswordInput)

    class Meta:
        model = User
        fields = ("email",)

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


# =========================
# User Change Form
# =========================
class UserChangeForm(forms.ModelForm):
    """Form for updating users in admin"""
    password = ReadOnlyPasswordHashField()

    class Meta:
        model = User
        fields = (
            "email",
            "password",
            "is_active",
            "is_staff",
            "is_superuser",
        )

    def clean_password(self):
        return self.initial["password"]


# =========================
# User Admin
# =========================
@admin.register(User)
class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm

    list_display = (
        "email",
        "is_staff",
        "is_active",
        "created_at",
    )
    list_filter = ("is_staff", "is_superuser", "is_active", "created_at")
    ordering = ("email",)
    search_fields = ("email",)

    fieldsets = (
        (None, {"fields": ("email", "password")}),
        (
            "Permissions",
            {
                "fields": (
                    "is_active",
                    "is_staff",
                    "is_superuser",
                    "groups",
                    "user_permissions",
                )
            },
        ),
        ("Important dates", {"fields": ("last_login", "created_at", "updated_at")}),
    )

    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": ("email", "password1", "password2"),
            },
        ),
    )

    filter_horizontal = ("groups", "user_permissions")
    readonly_fields = ("created_at", "updated_at")

    def get_readonly_fields(self, request, obj=None):
        if obj:
            return self.readonly_fields
        return self.readonly_fields
