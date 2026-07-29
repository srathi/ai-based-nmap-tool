from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.auth.jwt import get_current_user
from backend.database import get_db
from backend.models.user import User, UserRole


class RoleChecker:
    def __init__(self, allowed_roles: list[UserRole]):
        self.allowed_roles = allowed_roles

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        if user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user.role.value}' is not permitted for this action",
            )
        return user


admin_only = RoleChecker([UserRole.ADMIN])
operator_and_above = RoleChecker([UserRole.ADMIN, UserRole.OPERATOR])
viewer_and_above = RoleChecker([UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER])


def require_target_authorization(target, user: User) -> bool:
    if user.role == UserRole.ADMIN:
        return True
    if user.role == UserRole.OPERATOR:
        return True
    if target.created_by == user.id:
        return True
    return False


def can_scan(user: User) -> bool:
    return user.role in (UserRole.ADMIN, UserRole.OPERATOR)
