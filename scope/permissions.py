from rest_framework import permissions


class IsScopeOwnerOrSuperAdmin(permissions.BasePermission):
    """
    Permission class that allows:
    - Super admins to access any scope
    - Regular admins to access only their own scopes
    """

    def has_permission(self, request, view):
        # Must be authenticated
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Super admin can access all
        if request.user.is_superuser:
            return True

        # Regular admin can only access their own scopes
        return str(obj.admin_id) == str(request.user.id)


class CanModifyScope(permissions.BasePermission):
    """
    Permission class that allows scope modification:
    - Super admins can modify any scope
    - Regular admins can modify only their own UNLOCKED scopes
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        # Super admin can modify all
        if request.user.is_superuser:
            return True

        # Regular admin must own the scope
        if str(obj.admin_id) != str(request.user.id):
            return False

        # Scope must be unlocked for regular admins
        return not obj.is_locked


class CanLockScope(permissions.BasePermission):
    """
    Permission class for locking scopes:
    - Super admins can lock/unlock any scope
    - Regular admins can only LOCK their own scopes (not unlock)
    """

    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def has_object_permission(self, request, view, obj):
        action = request.data.get("action", "lock")

        # Super admin can lock/unlock any scope
        if request.user.is_superuser:
            return True

        # Regular admin permissions
        if str(obj.admin_id) != str(request.user.id):
            return False

        # Regular admins can only lock, not unlock
        if action == "unlock":
            return False

        return True


class IsSuperAdmin(permissions.BasePermission):
    """
    Permission class that only allows super admins.
    """

    def has_permission(self, request, view):
        return (
            request.user and
            request.user.is_authenticated and
            request.user.is_superuser
        )
