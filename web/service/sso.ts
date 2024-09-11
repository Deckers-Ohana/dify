import { get } from './base'
import { API_PREFIX } from '@/config'

export const getUserSAMLSSOUrl = () => {
  return get<{ url: string }>('/enterprise/sso/saml/login')
}

export const getUserOIDCSSOUrl = () => {
  return get<{ url: string; state: string }>('/enterprise/sso/oidc/login')
}

export const getUserOAuth2SSOUrl = () => {
  return `${API_PREFIX}/oauth/login/divzen`
}
