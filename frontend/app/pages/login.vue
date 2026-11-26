<script setup lang="ts">
import { ArrowLeft, ArrowRight, Fingerprint, Shield } from '@lucide/vue'

useHead({ title: 'Sign in · AEGIS' })
</script>

<template>
  <main class="login-screen">
    <NuxtLink to="/" class="back-link"><ArrowLeft :size="16" /> Workspace</NuxtLink>
    <div class="login-frame">
      <aside class="login-brand">
        <div class="login-visual" aria-hidden="true">
          <div class="auth-orbit orbit-outer" />
          <div class="auth-orbit orbit-inner" />
          <div class="auth-core"><Shield :size="58" :stroke-width="1.2" /><i /></div>
        </div>
        <span class="login-brand-name">AEGIS</span>
        <p>Threat intelligence workspace</p>
      </aside>
      <section class="login-form" aria-labelledby="sign-in-heading">
        <h1 id="sign-in-heading">Sign in to AEGIS</h1>
        <p>Use OB Auth to sign in, register or recover your account.</p>
        <UButton class="primary-action submit-action" to="/auth/login" external>
          Continue to OB Auth <ArrowRight :size="16" />
        </UButton>
        <div class="factor-note"><Fingerprint :size="17" /> A verified email is required. Add an authenticator when signing in with a password.</div>
      </section>
    </div>
  </main>
</template>

<style scoped>
.login-screen { min-height: 100svh; display: grid; place-items: center; padding: 78px 24px 48px; position: relative; background: radial-gradient(ellipse at 17% 12%, #15332f 0, transparent 42%), var(--bg); }
.back-link { display: inline-flex; gap: 8px; align-items: center; position: absolute; top: 25px; left: clamp(24px, 5vw, 72px); color: var(--muted); }
.back-link:hover { color: var(--mint); }
.login-frame { width: min(100%, 940px); min-height: 550px; display: grid; grid-template-columns: minmax(0, .95fr) minmax(0, 1.05fr); background: var(--panel); border-radius: 30px; overflow: hidden; border: 1px solid var(--border); box-shadow: 24px 28px 90px #03070cc4, inset 0 1px #aecbdf13; }
.login-brand { display: grid; align-content: center; justify-items: center; gap: 9px; position: relative; overflow: hidden; min-height: 100%; padding: 38px; color: var(--muted); border-right: 1px solid #2b4e50; background: radial-gradient(ellipse at 50% 41%, #1b453e 0, #122833 42%, #0e1722 76%); }
.login-brand::before { content: ''; position: absolute; inset: 0; opacity: .3; background-image: linear-gradient(#548e8b30 1px, transparent 1px), linear-gradient(90deg, #548e8b30 1px, transparent 1px); background-size: 24px 24px; mask-image: radial-gradient(ellipse, black, transparent 75%); pointer-events: none; }
.login-visual { width: 228px; height: 220px; position: relative; display: grid; place-items: center; }
.auth-orbit { position: absolute; border-radius: 50%; border: 1px solid #5df6d334; }
.orbit-outer { width: 202px; height: 202px; box-shadow: 0 0 26px #50e1ba15, inset 0 0 26px #50e1ba15; }
.orbit-inner { width: 158px; height: 158px; border-style: dashed; }
.orbit-outer::after, .orbit-inner::after { content: ''; position: absolute; width: 7px; height: 7px; border-radius: 50%; background: var(--mint); box-shadow: 0 0 13px var(--mint); }
.orbit-outer::after { top: 26px; right: 27px; }
.orbit-inner::after { bottom: 17px; left: 23px; }
.auth-core { color: var(--mint); position: relative; width: 114px; height: 114px; display: grid; place-items: center; border: 1px solid #5fbaa18a; border-radius: 34px; background: linear-gradient(145deg, #24594d, #101f2c); box-shadow: 0 17px 40px #070c13a1, inset 0 1px #9dffdf48; }
.auth-core i { position: absolute; width: 7px; height: 7px; border-radius: 50%; background: var(--mint); box-shadow: 0 0 13px var(--mint); }
.login-brand-name { color: var(--text); font-size: 37px; letter-spacing: .19em; line-height: 1; font-weight: 700; }
.login-brand p { text-align: center; }
.login-form { display: flex; flex-direction: column; align-self: center; min-width: 0; gap: 17px; padding: clamp(26px, 5vw, 61px); }
.login-form h1 { font-size: clamp(26px, 3.1vw, 37px); font-weight: 700; letter-spacing: -.045em; line-height: 1.1; }
.login-form p { color: var(--muted); line-height: 1.55; }
.submit-action { justify-content: center; min-height: 46px; width: 100%; border-radius: 10px; }
.factor-note { display: flex; gap: 8px; align-items: center; color: var(--muted); padding-top: 14px; border-top: 1px solid var(--border); font-size: 12px; }
.factor-note svg { color: var(--mint); flex: none; }
@media (max-width: 740px) {
  .login-screen { padding: 66px 15px 28px; }
  .login-frame { grid-template-columns: minmax(0, 1fr); max-width: 480px; border-radius: 21px; }
  .login-brand { min-height: 134px; padding: 24px; border-right: 0; border-bottom: 1px solid #2b4e50; }
  .login-brand-name { font-size: 29px; }
  .login-visual { display: none; }
}
</style>
