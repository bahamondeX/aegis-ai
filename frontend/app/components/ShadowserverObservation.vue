<script setup lang="ts">
import type { ShadowserverContext } from '../../investigations/exposure'

defineProps<{ context: ShadowserverContext }>()
const countFormat = new Intl.NumberFormat('es-PE')
</script>

<template>
  <p class="exposure-citation">
    Shadowserver · {{ context.area.country_iso2 }} · {{ context.window_start }}
    · Cobertura parcial · {{ context.unit }}
    <br><span v-if="context.count === null">Recuento nacional no publicado</span>
    <span v-else>{{ countFormat.format(context.count) }} observadas</span>
  </p>
</template>
