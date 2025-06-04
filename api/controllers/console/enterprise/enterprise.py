
from flask_restful import Resource, reqparse

from controllers.console import api
from controllers.console.wraps import setup_required


class EnterpriseAppPermission(Resource):
    @setup_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("appId", type=str, required=True, location="args")
        args = parser.parse_args()
        #根据appId查询这个app，然后判断这个app的创建人是不是在当前企业下
        return {"result": "true"}

class EnterpriseAppSubjects(Resource):
    @setup_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("appId", type=str, required=True, location="args")
        args = parser.parse_args()
        #根据appId查询这个app，然后判断这个app的创建人是不是在当前企业下
        return {"groups": [],"members":[]}


api.add_resource(EnterpriseAppPermission, "/enterprise/webapp/permission")
api.add_resource(EnterpriseAppSubjects, "/enterprise/webapp/app/subjects")
