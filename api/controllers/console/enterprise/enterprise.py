import secrets

from flask import current_app, make_response, redirect
from flask_login import current_user
from flask_restful import Resource, reqparse

from controllers.console import api
from controllers.console.wraps import setup_required
from services.enterprise.enterprise_sso_service import EnterpriseSSOService



class EnterpriseAppPermission(Resource):
    @setup_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("appId", type=str, required=True, location="args")
        args = parser.parse_args()
        #根据appId查询这个app，然后判断这个app的创建人是不是在当前企业下
        return "True"

api.add_resource(EnterpriseAppPermission, "/enterprise/webapp/permission")
