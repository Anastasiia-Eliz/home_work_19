"""`POST /auth` — получает логин и пароль из Body запроса в виде JSON, далее проверяет соотвествие с данными в БД (есть ли такой пользователь, такой ли у него пароль)
и если всё оk — генерит пару access_token и refresh_token и отдает их в виде JSON.

`PUT /auth` — получает refresh_token из Body запроса в виде JSON, далее проверяет refresh_token и если он не истек и валиден — генерит пару access_token и refresh_token и отдает их в виде JSON."""

from flask import request, abort
from flask_restx import Namespace, Resource
from container import auth_service

auth_ns = Namespace("auth")

@auth_ns.route("/")
class AuthView(Resource):
	def post(self):
		data = request.json
		username = data.get("username", None)
		password = data.get("password", None)
		if None is [username, password]:
			return abort(400)

		tokens = auth_service.generate_tokens(username, password)
		if tokens:
			return tokens, 201
		else:
			return "error", 400

	def put(self):
		data = request.json
		ref_token = data.get("refresh_token")
		if ref_token is None:
			return abort (400)
		tokens = auth_service.approve_refresh_token (ref_token)
		if tokens:
			return tokens, 201
		else:
			return "error", 400
