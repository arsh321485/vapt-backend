# permissions.py
from rest_framework import permissions

class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Allow update only if request.user is the location.admin (owner) or is staff/superuser.
    """

    def has_object_permission(self, request, view, obj):
        # obj is a Location instance
        if request.user and request.user.is_authenticated:
            if request.user.is_staff or request.user.is_superuser:
                return True
            return getattr(obj, 'admin', None) == request.user
        return False
