import { createAuthClient } from '@oscarbahamonde/ob-auth/core'

interface WorkspaceAccount {
  subject: string
  username: string
  email: string
  provider: 'email' | 'Google'
  photo: string | null
}

interface AccountResponse {
  profile: {
    user_id: string
    username: string
    email: string
    provider: 'password' | 'google'
    photo: string | null
  }
  tenant_id: string
}

export function useOperatorAuth() {
  const account = useState<WorkspaceAccount | null>('operator-account', () => null)
  const sessionIdentity = useState('operator-session-identity', () => '')
  const blocked = useState('operator-access-blocked', () => false)
  const loading = useState('operator-access-loading', () => true)
  const revision = useState('operator-access-revision', () => 0)
  const error = useState('operator-access-error', () => '')
  const development = import.meta.dev && useRuntimeConfig().public.localTokenAuth
  const localToken = useState('operator-local-token', () => '')
  const authenticated = computed(() => Boolean(account.value || localToken.value))
  const signedIn = computed(() => authenticated.value || blocked.value)
  const client = createAuthClient()

  function acceptLocal(value: string) {
    if (!development || !/^[\w.-]{1,8192}$/.test(value)) throw new Error('Enter a valid development token')
    localToken.value = value
    sessionIdentity.value = crypto.randomUUID()
  }

  function requestHeaders(): Record<string, string> {
    return localToken.value ? { Authorization: 'Bearer ' + localToken.value } : {}
  }

  async function refreshAccount() {
    if (development) { loading.value = false; return }
    const current = ++revision.value
    loading.value = true
    error.value = ''
    try {
      const response = await fetch('/api/aegis/v1/account', { cache: 'no-store' })
      if (current !== revision.value) return
      if (response.status === 401 || response.status === 403) {
        account.value = null
        sessionIdentity.value = ''
        blocked.value = response.status === 403
        return
      }
      if (!response.ok) throw new Error('Account unavailable')
      const { profile, tenant_id } = await response.json() as AccountResponse
      if (current !== revision.value) return
      account.value = {
        subject: profile.user_id, username: profile.username, email: profile.email,
        provider: profile.provider === 'google' ? 'Google' : 'email', photo: profile.photo,
      }
      sessionIdentity.value = tenant_id + ':' + profile.user_id
      blocked.value = false
    } catch {
      if (current !== revision.value) return
      account.value = null
      sessionIdentity.value = ''
      blocked.value = false
      error.value = 'Workspace access could not be verified. Try again.'
    } finally {
      if (current === revision.value) loading.value = false
    }
  }

  async function signOut() {
    if (!development) {
      try { await client.logout() }
      catch { error.value = 'Sign-out could not be completed. Try again.'; return }
    }
    revision.value++
    loading.value = false
    account.value = null
    blocked.value = false
    sessionIdentity.value = ''
    localToken.value = ''
    error.value = ''
  }

  return {
    account, authenticated, signedIn, blocked, loading, error, development, sessionIdentity,
    acceptLocal, requestHeaders, localToken, refreshAccount, signOut,
  }
}
