import jwt
from flask import request, abort
from constants import JWT_SECRET, JWT_ALGO


def auth_requered(func):
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)
        token = request.headers["Authorization"]

        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
        except Exception as e:
            print(f"JWT Decode error: {e}")
            abort(401)
        return func(*args, **kwargs)
    return wrapper


def admin_requered(func):
    def wrapper(*args, **kwargs):
        if "Authorization" not in request.headers:
            abort(401)
        token = request.headers["Authorization"]
        role = None
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            role = data.get("role", "user")
        except Exception as e:
            print(f"JWT decode error: {e}")
            abort(401)
        if role != "admin":
            abort(403)
        return func(*args, **kwargs)

    return wrapper
