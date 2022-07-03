from constans import SECRET, ALGO
from service.user import UserService
from flask import abort
import jwt
import datetime
import calendar
class AuthService:
	def __init__(self, user_service: UserService):
		self.user_service = user_service

	def generate_tokens(self, username, password, is_refresh=False):
		user = self.user_service.get_by_username(username)

		if user is None:
			raise abort(404)
		if not is_refresh:
			if not self.user_service.compare_password(user.password, password):
				abort(400)

		data = {
			"username": user.username,
			"role": user.role
		}
		# access token on 30 min
		min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
		data["exp"] = calendar.timegm(min30.timetuple())
		access_token = jwt.encode(data, SECRET, algorithm=ALGO)

		#refresh, 30 days
		day30 = datetime.datetime.utcnow() + datetime.timedelta(days=30)
		data["exp"] = calendar.timegm(day30.timetuple())
		refresh_token = jwt.encode(data, SECRET, algorithm=ALGO)

		return {"access_token": access_token, "refresh_token": refresh_token}

	def approve_refresh_token(self, refresh_token):
		data = jwt.decode(refresh_token, SECRET, algorithms=ALGO)
		username = data['username']
		user = self.user_service.get_by_username(username)

		if not user:
			raise Exception("bad token")
		return self.generate_tokens(username, user.password, is_refresh=True)