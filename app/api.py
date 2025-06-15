from flask_restful import Resource
from .db import get_all_users

class UserAPI(Resource):
    def get(self):
        users = get_all_users()
        return [{'id': u[0], 'username': u[1]} for u in users]
