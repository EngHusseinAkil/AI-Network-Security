from .models import Permission, ROLE_PERMISSIONS, Role


class AuthorizationService:
    def permissions_for(self, role):
        try:
            permissions = ROLE_PERMISSIONS[Role(role)]
        except (ValueError, KeyError):
            return frozenset()
        return frozenset(permission.value for permission in permissions)

    def allowed(self, user, permission):
        value = permission.value if isinstance(permission, Permission) else permission
        return bool(user and value in user.permissions)
