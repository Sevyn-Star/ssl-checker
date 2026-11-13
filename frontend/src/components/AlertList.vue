<script setup lang="ts">
import type { Alert } from "../types";

defineProps<{
  alerts: Alert[];
}>();
</script>

<template>
  <ul v-if="alerts.length" class="alerts">
    <li v-for="(alert, index) in alerts" :key="index">{{ alert.message }}</li>
  </ul>
</template>

<style scoped>
.alerts {
  margin: 8px 0 0;
  padding: 0;
  list-style: none;
}

li {
  margin: 0;
  padding: 10px 0 0;
  font-size: 15px;
  line-height: 1.55;
}
</style>
