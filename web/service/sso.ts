import { get } from './base'
import { API_PREFIX } from '@/config'

export const getUserSAMLSSOUrl = (invite_token?: string) => {
  const url = invite_token ? `/enterprise/sso/saml/login?invite_token=${invite_token}` : '/enterprise/sso/saml/login'
  return get<{ url: string }>(url)
}

export const getUserOIDCSSOUrl = (invite_token?: string) => {
  const url = invite_token ? `/enterprise/sso/oidc/login?invite_token=${invite_token}` : '/enterprise/sso/oidc/login'
  return get<{ url: string; state: string }>(url)
}

export const getUserOAuth2SSOUrl = (invite_token?: string) => {
  const url = invite_token ? `/enterprise/sso/oauth2/login?invite_token=${invite_token}` : '/enterprise/sso/oauth2/login'
  return get<{ url: string; state: string }>(url)
}

// export const getUserOAuth2SSOUrl = () => {
//     return `${API_PREFIX}/oauth/login/divzen`
// }
