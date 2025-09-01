import secrets

from flask import current_app, make_response, redirect
from flask_restx import Resource, reqparse

from controllers.console import api
from controllers.console.wraps import setup_required
from services.enterprise.enterprise_sso_service import EnterpriseSSOService


class EnterpriseSSOSamlLogin(Resource):
    @setup_required
    def get(self):
        return EnterpriseSSOService.get_sso_saml_login()


class EnterpriseSSOSamlAcs(Resource):
    @setup_required
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("SAMLResponse", type=str, required=True, location="form")
        args = parser.parse_args()
        saml_response = args["SAMLResponse"]
        try:
            token = EnterpriseSSOService.post_sso_saml_acs(saml_response)
            return redirect(f"{current_app.config.get('CONSOLE_WEB_URL')}/signin?console_token={token}")
        except Exception as e:
            return redirect(f"{current_app.config.get('CONSOLE_WEB_URL')}/signin?message={str(e)}")


class EnterpriseSSOOidcLogin(Resource):
    @setup_required
    def get(self):
        # 生成安全的随机 state 参数
        state = secrets.token_urlsafe(16)  # 生成 16字节 的随机字符串（Base64编码）
        data = EnterpriseSSOService.get_sso_oidc_login(state)
        # 创建响应对象（两种方式任选）
        resp = make_response(data)  # 方式1：自动转换JSON
        # 或 resp = Response(json.dumps(auth_data), mimetype='application/json')  # 方式2
        # 设置企业级安全 Cookie
        resp.set_cookie(
            key="user-oidc-state",
            value=state,  # 实际应使用加密后的值
            max_age=86400,  # 24小时有效期
            # domain= '127.0.0.1',
            secure=True,  # 强制 HTTPS
            httponly=True,  # 禁止 JS 访问
            samesite="Lax",  # 同站策略
            path="/",  # 限定 API 路径
        )
        return resp


class EnterpriseSSOOidcCallback(Resource):
    @setup_required
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("state", type=str, required=True, location="args")
        parser.add_argument("code", type=str, required=True, location="args")
        parser.add_argument("user-oidc-state", type=str, required=True, location="cookies")
        args = parser.parse_args()
        try:
            token = EnterpriseSSOService.get_sso_oidc_callback(args)
            return redirect(
                f"{current_app.config.get('CONSOLE_WEB_URL')}/signin?access_token={token.get('access_token')}&refresh_token={token.get('refresh_token')}"
            )
        except Exception as e:
            return redirect(f"{current_app.config.get('CONSOLE_WEB_URL')}/signin?message={str(e)}")


api.add_resource(EnterpriseSSOSamlLogin, "/enterprise/sso/saml/login")
api.add_resource(EnterpriseSSOSamlAcs, "/enterprise/sso/saml/acs")
api.add_resource(EnterpriseSSOOidcLogin, "/enterprise/sso/oidc/login")
api.add_resource(EnterpriseSSOOidcCallback, "/enterprise/sso/oidc/callback")
