export enum SSOProtocol {
  SAML = 'saml',
  OIDC = 'oidc',
  OAuth2 = 'oauth2',
}

export enum LicenseStatus {
  NONE = 'none',
  INACTIVE = 'inactive',
  ACTIVE = 'active',
  EXPIRING = 'expiring',
  EXPIRED = 'expired',
  LOST = 'lost',
}

type License = {
  status: LicenseStatus
  expired_at: string | null
}

export type SystemFeatures = {
  sso_enforced_for_signin: boolean
  sso_enforced_for_signin_protocol: SSOProtocol | ''
  sso_enforced_for_web: boolean
  sso_enforced_for_web_protocol: SSOProtocol | ''
  enable_web_sso_switch_component: boolean
  enable_email_code_login: boolean
  enable_email_password_login: boolean
  enable_social_oauth_login: boolean
  is_allow_create_workspace: boolean
  is_allow_register: boolean
  is_email_setup: boolean
  license: License
}

export const defaultSystemFeatures: SystemFeatures = {
  sso_enforced_for_signin: true,
  sso_enforced_for_signin_protocol: 'oauth2',
  sso_enforced_for_web: true,
  sso_enforced_for_web_protocol: 'oauth2',
  enable_web_sso_switch_component: true,
  enable_email_code_login: true,
  enable_email_password_login: true,
  enable_social_oauth_login: true,
  is_allow_create_workspace: true,
  is_allow_register: true,
  is_email_setup: true,
  license: {
    status: LicenseStatus.ACTIVE,
    expired_at: '',
  },
}
