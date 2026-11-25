<script setup lang="ts">
import type { AccountStatus, WorkspaceAccount } from '../composables/useOperatorAuth'

type Action = 'approve' | 'reject' | 'suspend' | 'restore'
interface UserListing {
  total: number
  pending: number
  approved: number
  suspended: number
  users: WorkspaceAccount[]
}
interface AuditEntry {
  actor: string
  target: string
  action: Action | 'activate_admin'
  timestamp: string
  outcome: string
}

const auth = useOperatorAuth()
const permitted = auth.administrator
const registry = ref<UserListing>()
const pendingOnly = ref(false)
const busy = ref(false)
const error = ref('')
const audit = ref<AuditEntry[]>([])
const selected = ref<WorkspaceAccount>()
const confirmation = ref<{ user: WorkspaceAccount, action: Action }>()
const active = computed(() => registry.value?.users.filter(user => user.enabled) ?? [])
const disabled = computed(() => (registry.value?.total ?? 0) - active.value.length)
const rows = computed(() => pendingOnly.value
  ? active.value.filter(user => user.status === 'PENDING_APPROVAL')
  : registry.value?.users ?? [])
const labels: Record<AccountStatus, string> = {
  PENDING_APPROVAL: 'Pending approval',
  APPROVED: 'Approved',
  REJECTED: 'Rejected',
  SUSPENDED: 'Suspended',
}
const actions: Record<AccountStatus, Action[]> = {
  PENDING_APPROVAL: ['approve', 'reject'],
  APPROVED: ['suspend'],
  REJECTED: [],
  SUSPENDED: ['restore'],
}
const timestamp = new Intl.DateTimeFormat('en', {
  dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC',
})

function headers() {
  return { Authorization: 'Bearer ' + auth.token.value }
}

function fail(message: string) { error.value = message }

async function refresh() {
  busy.value = true
  error.value = ''
  try {
    await auth.refreshAccount()
    if (permitted.value) {
      registry.value = await $fetch<UserListing>('/api/aegis/v1/admin/users', { headers: headers(), retry: 0 })
    }
  } catch { fail('The user directory could not be loaded. Sign in again or retry.') }
  finally {
    if (!permitted.value) registry.value = undefined
    busy.value = false
  }
}

async function history(user: WorkspaceAccount) {
  selected.value = user
  audit.value = []
  error.value = ''
  try {
    const entries = await $fetch<AuditEntry[]>('/api/aegis/v1/admin/users/' + encodeURIComponent(user.username) + '/audit', {
      headers: headers(), retry: 0,
    })
    if (selected.value?.subject === user.subject) audit.value = entries
  } catch { fail('Audit history could not be loaded.') }
}

async function apply() {
  const change = confirmation.value
  if (!change || busy.value) return
  busy.value = true
  error.value = ''
  try {
    await $fetch('/api/aegis/v1/admin/users/' + encodeURIComponent(change.user.username), {
      method: 'POST',
      headers: headers(),
      body: { action: change.action, expected_status: change.user.status },
      retry: 0,
    })
    confirmation.value = undefined
    await refresh()
    if (selected.value?.subject === change.user.subject) await history(change.user)
  } catch {
    confirmation.value = undefined
    fail('The action could not be applied. Refresh the directory and check the current status.')
  } finally { busy.value = false }
}

onMounted(() => { if (auth.signedIn.value) void refresh() })
</script>

<template>
  <main class="content admin-screen">
    <div class="page-heading">
      <div>
        <NuxtLink to="/">← Threat command center</NuxtLink>
        <h1>User administration<span>.</span></h1>
        <p>Review registrations, manage access and inspect account decisions.</p>
      </div>
      <UButton v-if="auth.signedIn.value" variant="outline" @click="auth.signOut">Sign out</UButton>
    </div>
    <section v-if="!permitted" class="panel sign-in">
      <h2>Administrator access required</h2>
      <p>Sign in with an authorized administrator account to manage workspace access.</p>
      <NuxtLink to="/">Return to sign-in</NuxtLink>
    </section>
    <template v-else>
      <dl v-if="registry" class="admin-kpis">
        <div class="panel"><dt>Registered accounts</dt><dd>{{ registry.total }}</dd></div>
        <div class="panel"><dt>Pending approvals</dt><dd>{{ active.filter(user => user.status === 'PENDING_APPROVAL').length }}</dd></div>
        <div class="panel"><dt>Approved</dt><dd>{{ active.filter(user => user.status === 'APPROVED').length }}</dd></div>
        <div class="panel"><dt>Suspended</dt><dd>{{ active.filter(user => user.status === 'SUSPENDED').length }}</dd></div>
        <div class="panel"><dt>Disabled in Cognito</dt><dd>{{ disabled }}</dd></div>
      </dl>
      <section class="panel admin-directory" aria-labelledby="directory-heading">
        <div class="identity-actions">
          <h2 id="directory-heading">Registered users</h2>
          <label><input v-model="pendingOnly" type="checkbox"> Pending only</label>
          <UButton variant="outline" :disabled="busy" @click="refresh">Refresh</UButton>
        </div>
        <p v-if="busy" role="status">Updating directory…</p>
        <p v-if="error" class="form-error" role="alert">{{ error }}</p>
        <div class="admin-table-wrap">
          <table v-if="rows.length" class="admin-table">
            <thead><tr><th scope="col">Account</th><th scope="col">Registered (UTC)</th><th scope="col">Provider</th><th scope="col">Status</th><th scope="col">Actions</th></tr></thead>
            <tbody>
              <tr v-for="user in rows" :key="user.subject">
                <th scope="row">{{ user.email ?? user.username }}<small>{{ user.username }}</small></th>
                <td>{{ timestamp.format(new Date(user.registered_at)) }}</td>
                <td>{{ user.provider === 'email' ? 'Email' : user.provider }}</td>
                <td>
                  {{ user.enabled ? labels[user.status] : 'Disabled in Cognito' }}
                  <small v-if="!user.enabled">Last decision · {{ labels[user.status] }}</small>
                  <small v-if="!user.email_verified">Email unverified</small>
                </td>
                <td>
                  <div class="identity-actions">
                    <UButton
                      v-for="action in !user.enabled || user.username === 'aegis-platform-admin' ? [] : actions[user.status]"
                      :key="action" variant="outline" size="xs" class="admin-action"
                      :disabled="busy || ((action === 'approve' || action === 'restore') && (!user.email_verified || !user.enabled))"
                      @click="confirmation = { user, action }"
                    >{{ action }}</UButton>
                    <UButton size="xs" variant="ghost" @click="history(user)">Audit history</UButton>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
          <p v-else-if="registry && !busy">No accounts match this view.</p>
        </div>
      </section>
      <section v-if="selected" class="panel admin-directory" aria-labelledby="audit-heading">
        <h2 id="audit-heading">Audit history · {{ selected.email ?? selected.username }}</h2>
        <ul v-if="audit.length">
          <li v-for="entry in audit" :key="entry.timestamp">
            {{ timestamp.format(new Date(entry.timestamp)) }} UTC · {{ entry.action }} · {{ entry.outcome }}
            <small>Actor {{ entry.actor }} · Target {{ entry.target }}</small>
          </li>
        </ul>
        <p v-else>No recorded decisions.</p>
      </section>
      <UModal :open="Boolean(confirmation)" title="Confirm account decision" @update:open="open => { if (!open && !busy) confirmation = undefined }">
        <template #body>
          <p>Apply <strong>{{ confirmation?.action }}</strong> to {{ confirmation?.user.email ?? confirmation?.user.username }}?</p>
        </template>
        <template #footer>
          <UButton variant="outline" :disabled="busy" @click="confirmation = undefined">Cancel</UButton>
          <UButton :disabled="busy" @click="apply">Confirm</UButton>
        </template>
      </UModal>
    </template>
  </main>
</template>
