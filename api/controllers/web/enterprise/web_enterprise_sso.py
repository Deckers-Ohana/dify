import logging
import secrets
import urllib.parse

from flask import current_app, make_response, redirect
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
        state = secrets.token_urlsafe(16)  #
        args = parser.parse_args()
        divzen_oauth = DivZenOAuth(
            client_id=dify_config.DIVZEN_CLIENT_ID,
            client_secret=dify_config.DIVZEN_CLIENT_SECRET,
            redirect_uri= dify_config.CONSOLE_API_URL+ "/api/enterprise/sso/members/oidc/callback",
        )
        auth_url = divzen_oauth.get_authorization_url(invite_token=state)

        data = {"url": auth_url, "state": state}
        # 创建响应对象（两种方式任选）
        resp = make_response(data)  # 方式1：自动转换JSON
        # 或 resp = Response(json.dumps(auth_data), mimetype='application/json')  # 方式2
        # 设置企业级安全 Cookie
        resp.set_cookie(
            key="web-oidc-state",
            value=state,  # 实际应使用加密后的值
            max_age=86400,  # 24小时有效期
            secure=True,  # 强制 HTTPS
            httponly=True,  # 禁止 JS 访问
            samesite="Lax",  # 同站策略
            path="/",  # 限定 API 路径
        )
        resp.set_cookie(
            key="web-app-code",
            value=args["app_code"],  # 实际应使用加密后的值
            max_age=86400,  # 24小时有效期
            secure=True,  # 强制 HTTPS
            httponly=True,  # 禁止 JS 访问
            samesite="Lax",  # 同站策略
            path="/",  # 限定 API 路径
        )
        return resp


class EnterpriseSSOOidcCallback(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("state", type=str, required=True, location="args")
        parser.add_argument("code", type=str, required=True, location="args")
        parser.add_argument("web-oidc-state", type=str, required=True, location="cookies")
        parser.add_argument("web-app-code", type=str, required=True, location="cookies")
        args = parser.parse_args()
        try:
            state_from_cookie = args["state"]
            app_code_from_cookie = args["web-app-code"]
            code_from_query = args["code"]
            state_from_cookies = args["web-oidc-state"]
            if state_from_cookies != state_from_cookie:
                raise Exception("invalid state or code")
            divzen_oauth = DivZenOAuth(
                client_id=dify_config.DIVZEN_CLIENT_ID,
                client_secret=dify_config.DIVZEN_CLIENT_SECRET,
                redirect_uri= dify_config.CONSOLE_API_URL + "/api/enterprise/sso/members/oidc/callback",
            )
            token = divzen_oauth.get_access_token(code=code_from_query)
            response = divzen_oauth.get_user_info(token=token.get("access_token"))

            if response is None or response.email is None or "gpt user group" not in response.group:
                logger.exception(response)
                raise Exception("User not authorized")
            token = EnterpriseSSOService.login_with_sso_at_web_app(response, app_code=app_code_from_cookie)
            params = {
                "web_sso_token": token,
                "redirect_url": "/chat/" + app_code_from_cookie
            }
            return redirect(
                f"{current_app.config.get('CONSOLE_WEB_URL')}/webapp-signin?{urllib.parse.urlencode(params)}")
        except Exception as e:
            print(e)
            return redirect(f"{current_app.config.get('CONSOLE_WEB_URL')}/webapp-signin?message={str(e)}")


api.add_resource(EnterpriseSSOOidcLogin, "/enterprise/sso/members/oidc/login")
api.add_resource(EnterpriseSSOOidcCallback, "/enterprise/sso/members/oidc/callback")
