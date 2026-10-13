from auth.authorization import AuthorizationService
from auth.models import AuthenticatedUser, Permission


def _user(role):
    service = AuthorizationService()
    return AuthenticatedUser("id", "login", role, tuple(service.permissions_for(role)))


def test_viewer_can_read_but_cannot_mutate():
    service = AuthorizationService()
    viewer = _user("viewer")
    assert service.allowed(viewer, Permission.DASHBOARD_VIEW)
    assert service.allowed(viewer, Permission.REPORT_EXPORT)
    assert not service.allowed(viewer, Permission.MONITORING_CONTROL)


def test_operator_cannot_manage_users_and_admin_can():
    service = AuthorizationService()
    assert not service.allowed(_user("operator"), Permission.USER_MANAGE)
    assert service.allowed(_user("admin"), Permission.USER_MANAGE)
    assert service.permissions_for("untrusted-role") == frozenset()
