"""
Fake in-memory database.
Replace `fake_users_db` and the functions here with your real ORM layer
(e.g. SQLAlchemy async session) without touching anything else.
"""

from app.core.security import DUMMY_HASH, get_password_hash, verify_password

fake_users_db: dict[str, dict] = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": (
            "$argon2id$v=19$m=65536,t=3,p=4"
            "$wagCPXjifgvUFBzq4hqe3w"
            "$CYaIb8sB+wtD+Vu/P4uod1+Qof8h+1g7bbDlBID48Rc"
        ),
        "disabled": False,
    }
}


def db_get_user(username: str) -> dict | None:
    return fake_users_db.get(username)


def db_create_user(username: str, email: str, password: str, full_name: str | None) -> dict:
    hashed = get_password_hash(password)
    record = {
        "username": username,
        "email": email,
        "full_name": full_name,
        "hashed_password": hashed,
        "disabled": False,
    }
    fake_users_db[username] = record
    return record


def db_authenticate(username: str, password: str) -> dict | None:
    user = db_get_user(username)
    if not user:
        verify_password(password, DUMMY_HASH)   # timing-attack mitigation
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user