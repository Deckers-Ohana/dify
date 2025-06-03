import os


class EnterpriseRequest:
    base_url = os.environ.get("ENTERPRISE_API_URL", "ENTERPRISE_API_URL")
    secret_key = os.environ.get("ENTERPRISE_API_SECRET_KEY", "ENTERPRISE_API_SECRET_KEY")

    proxies = {
        "http": "",
        "https": "",
    }

    @classmethod
    def send_request(cls, method, endpoint, json=None, params=None):
        headers = {"Content-Type": "application/json", "Enterprise-Api-Secret-Key": cls.secret_key}
        if "app-sso-setting" in endpoint:
            return {"enabled": True}
        url = f"{cls.base_url}{endpoint}"
        # response = requests.request(method, url, json=json, params=params, headers=headers)
        return {
            "accessModes": "public",
            "sso_enforced_for_signin": True,
            "sso_enforced_for_signin_protocol": "oidc",
            "sso_enforced_for_web": True,
            "sso_enforced_for_web_protocol": "oidc",
            "enable_web_sso_switch_component": True,
            "is_allow_create_workspace": True,
        }
