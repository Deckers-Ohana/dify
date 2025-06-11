import logging
from typing import Optional
from datetime import UTC, datetime, timedelta

from flask import request
from sqlalchemy import select
from sqlalchemy.orm import Session
from werkzeug.exceptions import NotFound

from configs import dify_config
from constants.languages import languages
from events.tenant_event import tenant_was_created
from extensions.ext_database import db
from libs.oauth import DivZenOAuth, OAuthUserInfo
from libs.passport import PassportService
from models import Account
from models.account import AccountStatus
from models.model import App, EndUser, Site
from services.account_service import AccountService, RegisterService, TenantService
from services.enterprise.base import EnterpriseRequest
from services.errors.account import AccountNotFoundError
from services.errors.workspace import WorkSpaceNotAllowedCreateError
from services.feature_service import FeatureService

logger = logging.getLogger(__name__)


class EnterpriseSSOService:
    @classmethod
    def get_sso_saml_login(cls) -> str:
        return EnterpriseRequest.send_request("GET", "/sso/saml/login")

    @classmethod
    def post_sso_saml_acs(cls, saml_response: str) -> str:
        response = EnterpriseRequest.send_request("POST", "/sso/saml/acs", json={"SAMLResponse": saml_response})
        if "email" not in response or response["email"] is None:
            logger.exception(response)
            raise Exception("Saml response is invalid")
        return cls.login_with_email(response.get("email"))

    @classmethod
    def get_sso_oidc_login(cls, state: str):
        divzen_oauth = DivZenOAuth(
            client_id=dify_config.DIVZEN_CLIENT_ID,
            client_secret=dify_config.DIVZEN_CLIENT_SECRET,
            redirect_uri=dify_config.CONSOLE_API_URL + "/console/api/enterprise/sso/oidc/callback",
        )
        auth_url = divzen_oauth.get_authorization_url(invite_token=state)
        return {"url": auth_url, "state": state}

    @classmethod
    def get_sso_oidc_callback(cls, args: dict):
        state_from_query = args["state"]
        code_from_query = args["code"]
        state_from_cookies = args["user-oidc-state"]
        if state_from_cookies != state_from_query:
            raise Exception("invalid state or code")
        divzen_oauth = DivZenOAuth(
            client_id=dify_config.DIVZEN_CLIENT_ID,
            client_secret=dify_config.DIVZEN_CLIENT_SECRET,
            redirect_uri=dify_config.CONSOLE_API_URL + "/console/api/enterprise/sso/oidc/callback",
        )
        token = divzen_oauth.get_access_token(code=code_from_query)
        response = divzen_oauth.get_user_info(token=token.get("access_token"))
        if response is None or response.email is None or "gpt user group" not in response.group:
            logger.exception(response)
            raise Exception("User not authorized")
        if response is None or response.email is None:
            logger.exception(response)
            raise Exception("OIDC response is invalid")
        return {"access_token": cls.login_with_email(response), "refresh_token": token.get("refresh_token")}

    @classmethod
    def login_with_email(cls, user_info: OAuthUserInfo) -> str:
        account = _generate_account("divzen", user_info)
        if account is None:
            raise Exception("account not found, please contact system admin to invite you to join in a workspace")
        if account.status == AccountStatus.BANNED:
            raise Exception("account is banned, please contact system admin")
        tenants = TenantService.get_join_tenants(account)
        if len(tenants) == 0:
            raise Exception("workspace not found, please contact system admin to invite you to join in a workspace")
        token = AccountService.get_account_jwt_token(account)
        return token

    @classmethod
    def login_with_sso_at_web_app(cls, user_info: OAuthUserInfo, app_code: str) -> str:
        site = db.session.query(Site).filter(Site.code == app_code).first()
        if not site:
            raise NotFound()
        # get app from db and check if it is normal and enable_site
        app_model = db.session.query(App).filter(App.id == site.app_id).first()
        if not app_model or app_model.status != "normal" or not app_model.enable_site:
            raise NotFound()
        end_user = db.session.query(EndUser).filter(EndUser.external_user_id == user_info.id).first()
        if not end_user:
            end_user = EndUser(
                tenant_id=app_model.tenant_id,
                app_id=app_model.id,
                type="browser",
                is_anonymous=False,
                name=user_info.name,
                external_user_id=user_info.id,
                session_id=user_info.id,
            )
            db.session.add(end_user)
            db.session.commit()
        exp_dt = datetime.now(UTC) + timedelta(hours=dify_config.ACCESS_TOKEN_EXPIRE_MINUTES * 24)
        exp = int(exp_dt.timestamp())
        payload = {
            "iss": site.app_id,
            "sub": "Web API Passport",
            "user_id": user_info.id,
            "session_id": user_info.email,
            "app_id": site.app_id,
            "app_code": app_code,
            "end_user_id": end_user.id,
            "external_user_id": user_info.id,
            "name": user_info.name,
            "token_source": "webapp_login_token",
            "exp": exp,
            "auth_type": "internal",
        }
        key: str = PassportService().issue(payload)
        return key


def _get_account_by_openid_or_email(provider: str, user_info: OAuthUserInfo) -> Optional[Account]:
    account: Optional[Account] = Account.get_by_openid(provider, user_info.id)

    if not account:
        with Session(db.engine) as session:
            account = session.execute(select(Account).filter_by(email=user_info.email)).scalar_one_or_none()

    return account


def _generate_account(provider: str, user_info: OAuthUserInfo):
    # Get account by openid or email.
    account = _get_account_by_openid_or_email(provider, user_info)

    if account:
        tenant = TenantService.get_join_tenants(account)
        if not tenant:
            if not FeatureService.get_system_features().is_allow_create_workspace:
                raise WorkSpaceNotAllowedCreateError()
            else:
                tenant = TenantService.create_tenant(f"{account.name}'s Workspace")
                TenantService.create_tenant_member(tenant, account, role="owner")
                account.current_tenant = tenant
                tenant_was_created.send(tenant)

    if not account:
        if not FeatureService.get_system_features().is_allow_register:
            raise AccountNotFoundError()
        account_name = user_info.name or "Dify"
        account = RegisterService.register(
            email=user_info.email, name=account_name, password=None, open_id=user_info.id, provider=provider
        )

        # Set interface language
        preferred_lang = request.accept_languages.best_match(languages)
        if preferred_lang and preferred_lang in languages:
            interface_language = preferred_lang
        else:
            interface_language = languages[0]
        account.interface_language = interface_language
        db.session.commit()

    # Link account
    AccountService.link_account_integrate(provider, user_info.id, account)

    return account
