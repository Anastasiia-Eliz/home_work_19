import hmac

from dao.user import UserDAO
from constans import PWD_HASH_SALT, PWD_HASH_ITERATIONS
import base64
import jwt
import hashlib
class UserService:
    def __init__(self, dao: UserDAO):
        self.dao = dao

    def get_one(self, uid):
        return self.dao.get_one(uid)

    def get_by_username(self, username):
        return self.dao.get_by_username(username)

    def get_all(self):
        return self.dao.get_all()

    def create(self, user_d):
        user_d["password"] = self.get_hash(user_d["password"])
        return self.dao.create(user_d)

    def update(self, user_d):
        self.dao.update(user_d)
        return self.dao

    def delete(self, uid):
        self.dao.delete(uid)

    def get_hash(self, password):
            return base64.b64encode(hashlib.pbkdf2_hmac(
                'sha256',
                password.encode('utf-8'),  # Convert the password to bytes
                PWD_HASH_SALT,
                PWD_HASH_ITERATIONS
            ))
    def compare_password(self, password_hash, other_password):
        decoded_digest = base64.b64decode(password_hash)

        hash_digest = hashlib.pbkdf2_hmac(
            'sha256',
            other_password.encode(),
            PWD_HASH_SALT,
            PWD_HASH_ITERATIONS
        )

        return hmac.compare_digest(decoded_digest, hash_digest)



