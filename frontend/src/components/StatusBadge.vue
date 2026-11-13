<script setup lang="ts">
import type { Tone } from "../status";

defineProps<{
  label: string;
  tone: Tone;
}>();
</script>

<template>
  <span class="badge" :class="`tone-${tone}`">{{ label }}</span>
</template>

<style scoped>
.badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 12px;
  border-radius: 999px;
  font-size: 13px;
  font-weight: 600;
  line-height: 1.5;
  white-space: nowrap;
}

.tone-ok {
  background: var(--green-bg);
}

.tone-d30 {
  background: var(--amber-bg);
}

.tone-d15 {
  background: var(--amber-deep-bg);
}

.tone-d7 {
  background: var(--orange-bg);
}

.tone-bad {
  background: var(--red-bg);
}
</style>
