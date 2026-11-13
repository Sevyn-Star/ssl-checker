<script setup lang="ts">
import { pillTone } from "../status";
import type { ChainItem } from "../types";
import StatusBadge from "./StatusBadge.vue";

defineProps<{
  items: ChainItem[];
}>();
</script>

<template>
  <section>
    <h2>证书链状态</h2>
    <ol>
      <li v-for="(item, index) in items" :key="`${item.role}-${index}`">
        <span class="index" aria-hidden="true">{{ index + 1 }}</span>
        <div>
          <div class="main">
            <strong>{{ item.role_label }}</strong>
            <StatusBadge :label="item.status_label" :tone="pillTone(item.status_label)" />
          </div>
          <p v-if="item.common_name" class="name">{{ item.common_name }}</p>
        </div>
      </li>
    </ol>
  </section>
</template>

<style scoped>
h2 {
  margin: 32px 0 0;
  font-size: 18px;
  line-height: 1.4;
}

ol {
  margin: 16px 0 0;
  padding: 0;
  list-style: none;
}

li {
  display: grid;
  grid-template-columns: 28px minmax(0, 1fr);
  column-gap: 12px;
  position: relative;
  padding-bottom: 20px;
}

li:last-child {
  padding-bottom: 0;
}

li:not(:last-child)::after {
  content: "";
  position: absolute;
  top: 28px;
  bottom: 0;
  left: 13px;
  width: 1px;
  background: var(--line);
}

.index {
  position: relative;
  z-index: 1;
  display: grid;
  width: 28px;
  height: 28px;
  place-items: center;
  border: 1px solid var(--line);
  border-radius: 999px;
  background: var(--card);
  font-size: 13px;
}

.main {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  min-height: 28px;
}

strong {
  font-size: 15px;
  font-weight: 600;
}

.name {
  margin: 4px 0 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.4;
  overflow-wrap: anywhere;
}
</style>
