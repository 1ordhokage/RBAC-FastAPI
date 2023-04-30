# Custom FastAPI Role-based access control

## Build with
 - Pyhton 3.10
 - FastAPI
 - SQLAlchemy + psycopg2, Alembic
 - passlib, python-jose

## Authentication backend
1. Transport: Bearer
2. Strategy: JWT

## Roles (customizable)
1. Admin
2. Viewer

## Access control (customizable)
1. Admin
  - Can create, update, delete, read users.
  - Can be created only by other admins.

2. Viewer (customizable)
  - Can register and authentificate.
  
## RBAC implementation
1. In `src/services/users.py` we create JWT with the ___role___ field in JWT payload:
```python
@staticmethod
    def create_token(user_id: int, user_role: str) -> JwToken:
        """Creates JWT.
        Args:
            user_id: user id.
            user_role: user role.
        Returns:
            JwToken: JWT.
        """
        now = datetime.utcnow()
        payload = {
            'iat': now,
            'exp': now + timedelta(seconds=jwt_settings.expires_seconds),
            'sub': str(user_id),
            'role': user_role
        }
        token = jwt.encode(
            payload,
            jwt_settings.secret_key,
            algorithm=jwt_settings.algorithm
        )
        return JwToken(access_token=token)
```
then we implement token verification:
```python
@staticmethod
    def verify_token(token: str) -> dict[str, str]:
        """Validates JWT.
        Args:
            token: given token.
        Returns:
            (int, str): user id and role.
        """
        try:
            payload = jwt.decode(
                token,
                jwt_settings.secret_key,
                algorithms=[jwt_settings.algorithm]
            )
        except JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Not authenticated'
            )
        return payload
```
... finally we are adding Bearer transport:
```python
oauth2_schema = OAuth2PasswordBearer(tokenUrl='/authorize')


def get_current_user_info(token: str = Depends(oauth2_schema)) -> dict:
    return UsersService.verify_token(token)
```

2. In `src/api/users.py` we implement role-checker dependency:
```python
class RoleChecker:
    """Permission-checker dependency."""
    def __init__(self, roles: list):
        self.roles = roles

    def __call__(self, payload: dict = Depends(get_current_user_info)):
        if payload.get('role') not in self.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail='You are not an admin'
            )


allowed_roles = RoleChecker([Roles.ADMIN.value])
```
now we can use our role-checker dependency in APIRouter decorators:
```python
@router.post(
    '/create',
    ...
    dependencies=[Depends(allowed_roles)],
    name='User creation'
)
def create_user(
  ...
)
```

## Getting started
`pip install -r requirements.txt`

`export PYTHONPATH="${PYTHONPATH}:/path/to/your/project/"`

`python3 src/main.py`
