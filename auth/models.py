from dataclasses import dataclass
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(str, Enum):
    DASHBOARD_VIEW = "dashboard_view"
    MONITORING_CONTROL = "monitoring_control"
    FLOW_PROCESS = "flow_process"
    FLOW_EVALUATE = "flow_evaluate"
    ALERT_CREATE = "alert_create"
    ALERT_LIFECYCLE_MANAGE = "alert_lifecycle_manage"
    NOTIFICATION_SEND = "notification_send"
    DEFENSIVE_ACTION_APPLY = "defensive_action_apply"
    DEFENSIVE_ACTION_REMOVE = "defensive_action_remove"
    REPORT_EXPORT = "report_export"
    USER_MANAGE = "user_manage"
    AUDIT_VIEW = "audit_view"


VIEWER_PERMISSIONS = {
    Permission.DASHBOARD_VIEW, Permission.REPORT_EXPORT,
}
OPERATOR_PERMISSIONS = VIEWER_PERMISSIONS | {
    Permission.MONITORING_CONTROL, Permission.FLOW_PROCESS,
    Permission.FLOW_EVALUATE, Permission.ALERT_CREATE,
    Permission.ALERT_LIFECYCLE_MANAGE, Permission.NOTIFICATION_SEND,
    Permission.DEFENSIVE_ACTION_APPLY, Permission.DEFENSIVE_ACTION_REMOVE,
}
ROLE_PERMISSIONS = {
    Role.VIEWER: VIEWER_PERMISSIONS,
    Role.OPERATOR: OPERATOR_PERMISSIONS,
    Role.ADMIN: OPERATOR_PERMISSIONS | {Permission.USER_MANAGE, Permission.AUDIT_VIEW},
}


@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    public_user_id: str
    login_label: str
    role: str
    permissions: tuple[str, ...]
    authenticated: bool = True

