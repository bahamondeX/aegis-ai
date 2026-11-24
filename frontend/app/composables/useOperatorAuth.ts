import { InMemoryWebStorage, UserManager, WebStorageStateStore } from 'oidc-client-ts'

let manager: UserManager | undefined

export function useOperatorAuth() {
  const token = useState('operator-token', () => '')
  const expires = useState('operator-expires', () => 0)
  const config = useRuntimeConfig().public
  const federated = Boolean(config.cognitoIssuer && config.cognitoClientId && config.cognitoDomain)
  const authenticated = computed(() => token.value.length > 0)

  function getManager() {
    if (!federated || !import.meta.client) throw new Error('Cognito is unavailable')
    if (manager) return manager
    const issuer = new URL(config.cognitoIssuer)
    const domain = new URL(config.cognitoDomain)
    if (issuer.protocol !== 'https:' || domain.protocol !== 'https:') {
      throw new Error('Cognito must use HTTPS')
    }
    manager = new UserManager({
      authority: issuer.origin + issuer.pathname,
      client_id: config.cognitoClientId,
      redirect_uri: window.location.origin + '/auth/callback',
      post_logout_redirect_uri: window.location.origin + '/',
      scope: 'openid',
      response_type: 'code',
      disablePKCE: false,
      automaticSilentRenew: false,
      monitorSession: false,
      loadUserInfo: false,
      userStore: new WebStorageStateStore({ store: new InMemoryWebStorage() }),
      stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
      metadata: {
        issuer: issuer.origin + issuer.pathname,
        authorization_endpoint: new URL('/oauth2/authorize', domain).href,
        token_endpoint: new URL('/oauth2/token', domain).href,
        jwks_uri: new URL(issuer.pathname + '/.well-known/jwks.json', issuer).href,
      },
    })
    return manager
  }

  function acceptLocal(value: string) {
    if (federated || !/^[\w.-]{1,8192}$/.test(value)) throw new Error('Enter a valid development token')
    token.value = value
    expires.value = 0
  }

  async function signIn() {
    await getManager().signinRedirect()
  }

  async function callback() {
    const user = await getManager().signinRedirectCallback()
    if (!user.access_token || user.expired) throw new Error('Cognito access token is unavailable')
    token.value = user.access_token
    expires.value = user.expires_at ?? 0
  }

  async function signOut() {
    token.value = ''
    expires.value = 0
    if (federated && import.meta.client) {
      await getManager().removeUser()
      const logout = new URL('/logout', config.cognitoDomain)
      logout.searchParams.set('client_id', config.cognitoClientId)
      logout.searchParams.set('logout_uri', window.location.origin + '/')
      window.location.assign(logout)
    }
  }

  return { token, expires, authenticated, federated, acceptLocal, signIn, callback, signOut }
}
