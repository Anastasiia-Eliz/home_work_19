from flask import request, abort
from constans import SECRET, ALGO
import jwt

def auth_required(func):
	"""Ограничение доступа так, чтобы к некоторым эндпоинтам
		был ограничен доступ для запросов без токена"""

	def wrapper(*args, **kwargs):
		if 'Authorization' not in request.headers:
			abort(401)
		token = request.headers['Authorization']
		try:
			jwt.decode(token, SECRET, algorithms=[ALGO])
		except Exception as e:
			print("JWT Decode Exception", e)
			abort(401)
		return func(*args, **kwargs)

	return wrapper

def admin_required(func):
	"""Ограничение доступа так, чтобы к некоторым эндпоинтам
	был доступ только у администраторов"""
	def wrapper(*args, **kwargs):
		if 'Authorization' not in request.headers:
			abort(401)

		token = request.headers["Authorization"]
		try:
			data = jwt.decode(token, SECRET, algorithms=[ALGO])
		except Exception as e:
			print("JWT Decode Exception", e)
			abort(401)
		else:
			if data["role"] == "admin":
				return func(*args, **kwargs)

		abort(403)

	return wrapper
