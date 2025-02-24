import logging

from flask import current_app, redirect
from flask_restful import Resource, reqparse

from configs import dify_config
from controllers.web import api
from libs.oauth import DivZenOAuth
from services.enterprise.enterprise_sso_service import EnterpriseSSOService

logger = logging.getLogger(__name__)


class EnterpriseSSOOidcLogin(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("app_code", type=str, required=True, location="args")
        parser.add_argument("redirect_url", type=str, required=True, location="args")
        args = parser.parse_args()
        divzen_oauth = DivZenOAuth(
            client_id=dify_config.DIVZEN_CLIENT_ID,
            client_secret=dify_config.DIVZEN_CLIENT_SECRET,
            redirect_uri=dify_config.CONSOLE_API_URL + "/api/enterprise/sso/oidc/callback",
        )
        auth_url = divzen_oauth.get_authorization_url(invite_token=args['app_code'])
        return {"url": auth_url, "state": args["app_code"]}


class EnterpriseSSOOidcCallback(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("state", type=str, required=True, location="args")
        parser.add_argument("code", type=str, required=True, location="args")
        parser.add_argument("web-oidc-state", type=str, required=True, location="cookies")
        args = parser.parse_args()
        try:
            state_from_query = args["state"]
            code_from_query = args["code"]
            state_from_cookies = args["web-oidc-state"]
            if state_from_cookies != state_from_query:
                raise Exception("invalid state or code")
            divzen_oauth = DivZenOAuth(
                client_id=dify_config.DIVZEN_CLIENT_ID,
                client_secret=dify_config.DIVZEN_CLIENT_SECRET,
                redirect_uri=dify_config.CONSOLE_API_URL + "/api/enterprise/sso/oidc/callback",
            )
            token = divzen_oauth.get_access_token(code=code_from_query)
            response = divzen_oauth.get_user_info(token=token.get("access_token"))
            if response is None or response.email is None or 'gpt user group' not in response.group:
                logger.exception(response)
                raise Exception("User not authorized")
            token = EnterpriseSSOService.login_with_email_at_web_app(response, app_code=state_from_query)
            params = f"web_sso_token={token}&redirect_url=/chat/{state_from_query}"
            return redirect(f"{current_app.config.get('CONSOLE_WEB_URL')}/webapp-signin?{params}")
        except Exception as e:
            return redirect(f"{current_app.config.get('CONSOLE_WEB_URL')}/webapp-signin?message={str(e)}")


api.add_resource(EnterpriseSSOOidcLogin, "/enterprise/sso/oidc/login")
api.add_resource(EnterpriseSSOOidcCallback, "/enterprise/sso/oidc/callback")