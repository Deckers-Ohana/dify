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

export enum InstallationScope {
  ALL = 'all',
  NONE = 'none',
  OFFICIAL_ONLY = 'official_only',
  OFFICIAL_AND_PARTNER = 'official_and_specific_partners',
}

type License = {
  status: LicenseStatus
  expired_at: string | null
}

export type SystemFeatures = {
  plugin_installation_permission: {
    plugin_installation_scope: InstallationScope
    restrict_to_marketplace_only: boolean
  }
  sso_enforced_for_signin: boolean
  sso_enforced_for_signin_protocol: SSOProtocol | ''
  sso_enforced_for_web: boolean
  sso_enforced_for_web_protocol: SSOProtocol | ''
  enable_marketplace: boolean
  enable_change_email: boolean
  enable_email_code_login: boolean
  enable_email_password_login: boolean
  enable_social_oauth_login: boolean
  is_allow_create_workspace: boolean
  is_allow_register: boolean
  is_email_setup: boolean
  license: License
  branding: {
    enabled: boolean
    login_page_logo: string
    workspace_logo: string
    favicon: string
    application_title: string
  }
  webapp_auth: {
    enabled: boolean
    allow_sso: boolean
    sso_config: {
      protocol: SSOProtocol | ''
    }
    allow_email_code_login: boolean
    allow_email_password_login: boolean
  }
}

export const defaultSystemFeatures: SystemFeatures = {
  plugin_installation_permission: {
    plugin_installation_scope: InstallationScope.ALL,
    restrict_to_marketplace_only: false,
  },
  sso_enforced_for_signin: true,
  sso_enforced_for_signin_protocol: SSOProtocol.OIDC,
  sso_enforced_for_web: false,
  sso_enforced_for_web_protocol: SSOProtocol.OIDC,
  enable_marketplace: true,
  enable_change_email: true,
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
  branding: {
    enabled: false,
    login_page_logo: '',
    workspace_logo: '',
    favicon: '',
    application_title: 'test title',
  },
  webapp_auth: {
    enabled: true,
    allow_sso: true,
    sso_config: {
      protocol: SSOProtocol.OIDC,
    },
    allow_email_code_login: true,
    allow_email_password_login: true,
  },
}

export enum DatasetAttr {
  DATA_API_PREFIX = 'data-api-prefix',
  DATA_PUBLIC_API_PREFIX = 'data-public-api-prefix',
  DATA_MARKETPLACE_API_PREFIX = 'data-marketplace-api-prefix',
  DATA_MARKETPLACE_URL_PREFIX = 'data-marketplace-url-prefix',
  DATA_PUBLIC_EDITION = 'data-public-edition',
  DATA_PUBLIC_AMPLITUDE_API_KEY = 'data-public-amplitude-api-key',
  DATA_PUBLIC_COOKIE_DOMAIN = 'data-public-cookie-domain',
  DATA_PUBLIC_SUPPORT_MAIL_LOGIN = 'data-public-support-mail-login',
  DATA_PUBLIC_SENTRY_DSN = 'data-public-sentry-dsn',
  DATA_PUBLIC_MAINTENANCE_NOTICE = 'data-public-maintenance-notice',
  DATA_PUBLIC_SITE_ABOUT = 'data-public-site-about',
  DATA_PUBLIC_TEXT_GENERATION_TIMEOUT_MS = 'data-public-text-generation-timeout-ms',
  DATA_PUBLIC_MAX_TOOLS_NUM = 'data-public-max-tools-num',
  DATA_PUBLIC_MAX_PARALLEL_LIMIT = 'data-public-max-parallel-limit',
  DATA_PUBLIC_TOP_K_MAX_VALUE = 'data-public-top-k-max-value',
  DATA_PUBLIC_INDEXING_MAX_SEGMENTATION_TOKENS_LENGTH = 'data-public-indexing-max-segmentation-tokens-length',
  DATA_PUBLIC_LOOP_NODE_MAX_COUNT = 'data-public-loop-node-max-count',
  DATA_PUBLIC_MAX_ITERATIONS_NUM = 'data-public-max-iterations-num',
  DATA_PUBLIC_MAX_TREE_DEPTH = 'data-public-max-tree-depth',
  DATA_PUBLIC_ALLOW_UNSAFE_DATA_SCHEME = 'data-public-allow-unsafe-data-scheme',
  DATA_PUBLIC_ENABLE_WEBSITE_JINAREADER = 'data-public-enable-website-jinareader',
  DATA_PUBLIC_ENABLE_WEBSITE_FIRECRAWL = 'data-public-enable-website-firecrawl',
  DATA_PUBLIC_ENABLE_WEBSITE_WATERCRAWL = 'data-public-enable-website-watercrawl',
  DATA_PUBLIC_ENABLE_SINGLE_DOLLAR_LATEX = 'data-public-enable-single-dollar-latex',
  NEXT_PUBLIC_ZENDESK_WIDGET_KEY = 'next-public-zendesk-widget-key',
  NEXT_PUBLIC_ZENDESK_FIELD_ID_ENVIRONMENT = 'next-public-zendesk-field-id-environment',
  NEXT_PUBLIC_ZENDESK_FIELD_ID_VERSION = 'next-public-zendesk-field-id-version',
  NEXT_PUBLIC_ZENDESK_FIELD_ID_EMAIL = 'next-public-zendesk-field-id-email',
  NEXT_PUBLIC_ZENDESK_FIELD_ID_WORKSPACE_ID = 'next-public-zendesk-field-id-workspace-id',
  NEXT_PUBLIC_ZENDESK_FIELD_ID_PLAN = 'next-public-zendesk-field-id-plan',
  DATA_PUBLIC_BATCH_CONCURRENCY = 'data-public-batch-concurrency',
}
