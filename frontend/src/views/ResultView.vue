<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";

import { checkHost } from "../api";
import AlertList from "../components/AlertList.vue";
import ChainList from "../components/ChainList.vue";
import DetailTable from "../components/DetailTable.vue";
import StatusBadge from "../components/StatusBadge.vue";
import { checkedAt, headline, issuerName, tone } from "../status";
import type { CheckFailure, CheckResult, CheckSuccess } from "../types";

const route = useRoute();
const router = useRouter();

const hostParam = computed(() => {
  const raw = route.params.host;
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (!value) return "";
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
});

const loading = ref(true);
const result = ref<CheckResult | null>(null);
const problem = ref("");
let requestId = 0;

const success = computed<CheckSuccess | null>(() => (result.value?.ok ? result.value : null));
const failed = computed<CheckFailure | null>(() => (result.value && !result.value.ok ? result.value : null));
const failureMessage = computed(() => problem.value || failed.value?.error.message || "");
const failureHost = computed(() => failed.value?.host || hostParam.value);

async function run(refresh: boolean) {
  const current = ++requestId;
  const host = hostParam.value;
  loading.value = true;
  problem.value = "";
  result.value = null;
  try {
    const body = await checkHost(host, refresh);
    if (current !== requestId) return;
    result.value = body;
  } catch (error) {
    if (current !== requestId) return;
    problem.value = error instanceof Error ? error.message : "检测服务暂时不可用。";
  } finally {
    if (current === requestId) loading.value = false;
  }
}

watch(hostParam, () => {
  void run(false);
}, { immediate: true });

function again() {
  void run(true);
}

function other() {
  void router.push({ name: "check" });
}
</script>

<template>
  <main class="page">
    <section class="card">
      <template v-if="loading">
        <h1>{{ hostParam }}</h1>
        <p class="pending">正在检测…</p>
      </template>

      <template v-else-if="failureMessage">
        <header class="top">
          <h1>{{ failureHost }}</h1>
          <StatusBadge label="检测失败" tone="bad" />
        </header>
        <p class="reason">{{ failureMessage }}</p>
        <div class="actions">
          <button type="button" @click="again">重新检测</button>
          <button type="button" @click="other">检测其他域名</button>
        </div>
      </template>

      <template v-else-if="success">
        <header class="top">
          <h1>{{ success.display_host }}</h1>
          <StatusBadge :label="success.overall.label" :tone="tone(success.overall, success.validity)" />
        </header>

        <div class="stats">
          <div>
            <p class="label">剩余有效期</p>
            <p class="figure" :class="`tone-${tone(success.overall, success.validity)}`">
              {{ headline(success.validity) }}
            </p>
          </div>
          <div>
            <p class="label">证书类型</p>
            <p class="figure">{{ success.certificate_type_label }}</p>
          </div>
        </div>

        <AlertList :alerts="success.alerts" />
        <DetailTable
          :host="success.display_host"
          :issuer="issuerName(success.issuer)"
          :not-before="success.validity.not_before"
          :not-after="success.validity.not_after"
          :matched="success.domain_match.matched"
          :chain-label="success.chain.label"
          :tls-version="success.tls.version"
        />
        <ChainList :items="success.chain.items" />
        <p class="note">检测时间：{{ checkedAt(success.checked_at) }}。信任结果基于本服务的系统根证书库。</p>
        <div class="actions">
          <button type="button" @click="other">检测其他域名</button>
          <button type="button" @click="again">重新检测</button>
        </div>
      </template>
    </section>
  </main>
</template>

<style scoped>
.page {
  min-height: 100vh;
  padding: 48px 20px 64px;
}

.card {
  max-width: 880px;
  margin: 0 auto;
  padding: 36px 40px 32px;
  border: 1px solid var(--line);
  border-radius: 24px;
  background: var(--card);
}

.top {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}

h1 {
  margin: 0;
  font-size: 32px;
  font-weight: 700;
  line-height: 1.25;
  letter-spacing: -0.02em;
  overflow-wrap: anywhere;
}

.pending,
.reason,
.label,
.figure,
.note {
  margin: 0;
}

.pending {
  margin-top: 16px;
  color: var(--muted);
  font-size: 16px;
}

.reason {
  margin-top: 18px;
  font-size: 16px;
  line-height: 1.6;
}

.stats {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 24px 32px;
  margin-top: 32px;
}

.label {
  margin-bottom: 8px;
  color: var(--muted);
  font-size: 14px;
}

.figure {
  font-size: 40px;
  font-weight: 700;
  line-height: 1.15;
  letter-spacing: -0.03em;
  overflow-wrap: anywhere;
}

.note {
  margin-top: 28px;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.6;
}

.actions {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 20px;
  margin-top: 20px;
}

button {
  padding: 0;
  border: 0;
  background: none;
  color: var(--text);
  font: inherit;
  font-weight: 600;
  text-decoration: underline;
  text-underline-offset: 3px;
  cursor: pointer;
}

button:focus-visible {
  outline: 2px solid var(--text);
  outline-offset: 3px;
}

@media (max-width: 719px) {
  .page {
    padding: 16px 12px 32px;
  }

  .card {
    padding: 24px 16px 20px;
  }

  h1 {
    font-size: 26px;
  }

  .stats {
    grid-template-columns: 1fr;
  }

  .figure {
    font-size: 34px;
  }
}
</style>
