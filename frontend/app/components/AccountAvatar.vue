<script setup lang="ts">
const props = defineProps<{ account: { subject: string; photo?: string | null } }>()
const failed = ref(false)
watch(() => props.account.photo, () => { failed.value = false })
const style = computed(() => {
  let seed = 0
  for (const letter of props.account.subject) seed = (Math.imul(seed, 31) + letter.charCodeAt(0)) >>> 0
  const hue = seed % 360
  return { background: `linear-gradient(${seed % 360}deg, hsl(${hue} 59% 31%), hsl(${(hue + 85) % 360} 72% 50%))` }
})
</script>

<template>
  <span class="avatar" :style="style" aria-hidden="true">
    <img v-if="account.photo && !failed" :src="account.photo" alt="" referrerpolicy="no-referrer" @error="failed = true">
    <span v-else class="avatar-mark" />
  </span>
</template>

<style scoped>
.avatar { display: inline-grid; place-items: center; flex: none; width: 2rem; height: 2rem; overflow: hidden; border-radius: 50%; }
.avatar img { width: 100%; height: 100%; object-fit: cover; }
.avatar-mark { width: 55%; height: 55%; border: 2px solid #ffffffb0; border-radius: 40% 60% 65% 35%; transform: rotate(-32deg); }
</style>
