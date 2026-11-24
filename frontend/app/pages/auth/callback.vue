<script setup lang="ts">
const auth = useOperatorAuth()
const error = ref('')
onMounted(async () => {
  try {
    await auth.callback()
    await navigateTo('/', { replace: true })
  } catch {
    error.value = 'Connection failed. Return to AEGIS and start a new sign-in.'
    window.history.replaceState(null, '', '/auth/callback')
  }
})
</script>

<template>
  <main class="auth-screen">
    <div class="panel auth-card" role="status">
      <h1>Workspace access</h1>
      <p>{{ error || 'Verifying your sign-in…' }}</p>
      <NuxtLink v-if="error" to="/">Return to AEGIS</NuxtLink>
    </div>
  </main>
</template>
