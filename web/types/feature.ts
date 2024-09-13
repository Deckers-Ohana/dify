export type SystemFeatures = {
  sso_enforced_for_signin: boolean
  sso_enforced_for_signin_protocol: string
  sso_enforced_for_web: boolean
  sso_enforced_for_web_protocol: string
  enable_web_sso_switch_component: boolean
}

export const defaultSystemFeatures: SystemFeatures = {
  sso_enforced_for_signin: true,
  sso_enforced_for_signin_protocol: 'oauth2',
  sso_enforced_for_web: true,
  sso_enforced_for_web_protocol: 'oauth2',
  enable_web_sso_switch_component: true,
}
