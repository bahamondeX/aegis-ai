<script setup lang="ts">
const emit = defineEmits<{ back: [], signIn: [] }>()
const { cognitoIssuer, cognitoClientId } = useRuntimeConfig().public
const email = ref('')
const password = ref('')
const code = ref('')
const phase = ref<'register' | 'verify' | 'complete'>('register')
const busy = ref(false)
const status = ref('')
const error = ref('')

async function send(operation: 'SignUp' | 'ConfirmSignUp' | 'ResendConfirmationCode', input: object) {
  const issuer = new URL(cognitoIssuer)
  if (issuer.protocol !== 'https:' || !/^cognito-idp\.[\w-]+\.amazonaws\.com$/.test(issuer.hostname)) {
    throw new Error('Registration service is unavailable')
  }
  const response = await fetch(issuer.origin, {
    method: 'POST',
    credentials: 'omit',
    headers: {
      'Content-Type': 'application/x-amz-json-1.1',
      'X-Amz-Target': 'AWSCognitoIdentityProviderService.' + operation,
    },
    body: JSON.stringify({ ClientId: cognitoClientId, ...input }),
    signal: AbortSignal.timeout(10_000),
  })
  if (response.ok) return
  const kind = (response.headers.get('x-amzn-errortype') ?? '').split(':')[0]
  switch (kind) {
    case 'CodeMismatchException':
      throw new Error('The verification code did not match. Check the latest message and try again.')
    case 'ExpiredCodeException':
      throw new Error('The verification code expired. Request a new one.')
    case 'InvalidPasswordException':
      throw new Error('Use at least 16 characters with uppercase, lowercase, a number and a symbol.')
    case 'TooManyRequestsException':
    case 'LimitExceededException':
      throw new Error('Please wait before trying again.')
    default:
      throw new Error(operation === 'SignUp'
        ? 'Registration could not be completed. Check your details or sign in if you already have an account.'
        : 'Verification could not be completed. Check the code or request a new one.')
  }
}

async function submit(resend = false) {
  if (busy.value) return
  busy.value = true
  error.value = ''
  status.value = ''
  const address = email.value.trim().toLowerCase()
  try {
    if (phase.value === 'register') {
      await send('SignUp', {
        Username: address,
        Password: password.value,
        UserAttributes: [{ Name: 'email', Value: address }],
      })
      email.value = address
      phase.value = 'verify'
    } else if (resend) {
      await send('ResendConfirmationCode', { Username: address })
      status.value = 'A new code was requested. Check your email.'
    } else {
      await send('ConfirmSignUp', { Username: address, ConfirmationCode: code.value.trim() })
      code.value = ''
      phase.value = 'complete'
    }
  } catch (failure) {
    error.value = failure instanceof Error ? failure.message : 'Registration is temporarily unavailable.'
  } finally {
    password.value = ''
    busy.value = false
  }
}
</script>

<template>
  <div>
    <h2 id="sign-in-heading">{{ phase === 'register' ? 'Request workspace access' : phase === 'verify' ? 'Verify your email' : 'Email verified' }}</h2>
    <form v-if="phase === 'register'" @submit.prevent="submit()">
      <p>Verify your email to submit your registration for administrator review.</p>
      <label><span>Email address</span><input v-model="email" type="email" autocomplete="email" maxlength="128" required></label>
      <label><span>Password</span><input v-model="password" type="password" autocomplete="new-password" minlength="16" maxlength="128" required></label>
      <p>Use 16 or more characters, including uppercase, lowercase, a number and a symbol.</p>
      <UButton type="submit" :disabled="busy" class="primary-action">Send verification code</UButton>
    </form>
    <form v-else-if="phase === 'verify'" @submit.prevent="submit()">
      <p>Enter the code sent to {{ email }}.</p>
      <label><span>Verification code</span><input v-model="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required></label>
      <div class="identity-actions">
        <UButton type="submit" :disabled="busy" class="primary-action">Verify email</UButton>
        <UButton type="button" variant="outline" :disabled="busy" @click="submit(true)">Resend code</UButton>
      </div>
    </form>
    <div v-else>
      <p>Sign in with your email address and password to check your approval status.</p>
      <UButton class="primary-action" @click="emit('signIn')">Continue to sign in</UButton>
    </div>
    <p v-if="error" class="form-error" role="alert">{{ error }}</p>
    <p v-if="status" role="status">{{ status }}</p>
    <UButton type="button" variant="ghost" :disabled="busy" @click="emit('back')">Back to sign-in</UButton>
  </div>
</template>
