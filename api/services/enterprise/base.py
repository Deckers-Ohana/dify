import os


class BaseRequest:
    proxies = {
        "http": "",
        "https": "",
    }
    base_url = ""
    secret_key = ""
    secret_key_header = ""

    @classmethod
    def send_request(cls, method, endpoint, json=None, params=None):
        headers = {"Content-Type": "application/json", cls.secret_key_header: cls.secret_key}
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


class EnterpriseRequest(BaseRequest):
    base_url = os.environ.get("ENTERPRISE_API_URL", "ENTERPRISE_API_URL")
    secret_key = os.environ.get("ENTERPRISE_API_SECRET_KEY", "ENTERPRISE_API_SECRET_KEY")
    secret_key_header = "Enterprise-Api-Secret-Key"


class EnterprisePluginManagerRequest(BaseRequest):
    base_url = os.environ.get("ENTERPRISE_PLUGIN_MANAGER_API_URL", "ENTERPRISE_PLUGIN_MANAGER_API_URL")
    secret_key = os.environ.get("ENTERPRISE_PLUGIN_MANAGER_API_SECRET_KEY", "ENTERPRISE_PLUGIN_MANAGER_API_SECRET_KEY")
    secret_key_header = "Plugin-Manager-Inner-Api-Secret-Key"
