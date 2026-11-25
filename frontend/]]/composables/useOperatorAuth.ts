import { InMemoryWebStorage, UserManager, WebStorageStateStore } from 'oidc-client-ts'

let manager: UserManager | undefined

export type AccountStatus = 'PENDING_APPROVAL' | 'APPROVED' | 'REJECTED' | 'SUSPENDED'

export interface WorkspaceAccount {
  subject: string
  username: string
  email: string | null
  email_verified: boolean
  registered_at: string
  provider: 'email' | 'Google' | 'other'
  status: AccountStatus
  administrator: boolean
  enabled: boolean
}

export function useOperatorAuth() {
  const token = useState('operator-token', () => '')
  const expires = useState('operator-expires', () => 0)
  const account = useState<WorkspaceAccount | null>('operator-account', () => null)
  const config = useRuntimeConfig().public
  const federated = Boolean(config.cognitoIssuer && config.cognitoClientId && config.cognitoDomain)
  const signedIn = computed(() => token.value.length > 0)
  const authenticated = computed(() => signedIn.value && (
    !config.identityApproval || (
      account.value?.status === 'APPROVED' && account.value.email_verified &&
      (account.value.username !== 'aegis-platform-admin' || account.value.administrator)
    )
  ))
  const administrator = computed(() => authenticated.value && Boolean(account.value?.administrator))

  function getManager(endpoint = '/oauth2/authorize') {
    if (!federated || !import.meta.client) throw new Error('Cognito is unavailable')
    if (manager && endpoint === '/oauth2/authorize') return manager
    const issuer = new URL(config.cognitoIssuer)
    const domain = new URL(config.cognitoDomain)
    if (issuer.protocol !== 'https:' || domain.protocol !== 'https:') {
      throw new Error('Cognito must use HTTPS')
    }
    const client = new UserManager({
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
        authorization_endpoint: new URL(endpoint, domain).href,
        token_endpoint: new URL('/oauth2/token', domain).href,
        jwks_uri: new URL(issuer.pathname + '/.well-known/jwks.json', issuer).href,
      },
    })
    if (endpoint === '/oauth2/authorize') manager = client
    return client
  }

  function acceptLocal(value: string) {
    if (federated || !/^[\w.-]{1,8192}$/.test(value)) throw new Error('Enter a valid development token')
    token.value = value
    expires.value = 0
  }

  async function signIn(method?: 'Google' | 'recovery') {
    const endpoint = method === 'recovery' ? '/forgotPassword' : undefined
    await getManager(endpoint).signinRedirect({
      extraQueryParams: method === 'Google' ? { identity_provider: 'Google' } : {},
    })
  }

  async function refreshAccount() {
    if (!config.identityApproval || !token.value) return
    const bearer = token.value
    try {
      const current = await $fetch<WorkspaceAccount>('/api/aegis/v1/account', {
        headers: { Authorization: 'Bearer ' + bearer },
        retry: 0,
      })
      if (bearer === token.value) account.value = current
    } catch (error) {
      if (bearer === token.value) account.value = null
      throw error
    }
  }

  async function callback() {
    const user = await getManager().signinRedirectCallback()
    if (!user.access_token || user.expired) throw new Error('Cognito access token is unavailable')
    token.value = user.access_token
    expires.value = user.expires_at ?? 0
    await refreshAccount()
  }

  async function signOut() {
    const bearer = token.value
    token.value = ''
    expires.value = 0
    account.value = null
    if (federated && import.meta.client) {
      const client = getManager()
      if (config.identityApproval && bearer) {
        try {
          await $fetch('/api/aegis/v1/account/logout', {
            method: 'POST', headers: { Authorization: 'Bearer ' + bearer }, retry: 0,
            timeout: 3000,
          })
        } catch { /* Fall back to Cognito refresh-token revocation and hosted logout. */ }
      }
      try { await client.revokeTokens(['refresh_token']) } catch { /* Hosted logout still clears Cognito's login session. */ }
      finally { await client.removeUser() }
      const logout = new URL('/logout', config.cognitoDomain)
      logout.searchParams.set('client_id', config.cognitoClientId)
      logout.searchParams.set('logout_uri', window.location.origin + '/')
      window.location.assign(logout)
    }
  }

  return {
    token, expires, account, signedIn, authenticated, administrator, federated,
    approvalRequired: config.identityApproval, googleEnabled: config.googleEnabled,
    acceptLocal, signIn, callback, refreshAccount, signOut,
  }
}
