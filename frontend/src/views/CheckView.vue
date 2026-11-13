<script setup lang="ts">
import { nextTick, ref } from "vue";
import { useRouter } from "vue-router";

import FeatureGrid from "../components/FeatureGrid.vue";

const router = useRouter();
const host = ref("");
const error = ref("");
const submitting = ref(false);

async function submit() {
  const value = host.value.trim();
  if (value === "") {
    error.value = "请输入域名，例如 example.com。";
    return;
  }
  error.value = "";
  submitting.value = true;
  await nextTick();
  await router.push({ name: "result", params: { host: value } });
}
</script>

<template>
  <main class="page">
    <section class="card">
      <form @submit.prevent="submit">
        <div class="top">
          <p class="brand">SSL Certificate Checker</p>
          <p class="pill">建议 MVP</p>
        </div>
        <h1>SSL 证书在线检测</h1>
        <p class="lead">检查 SSL/TLS 证书是否有效、是否即将过期，以及 HTTPS 配置是否正确。</p>
        <label for="host">输入域名</label>
        <input
          id="host"
          v-model="host"
          type="text"
          placeholder="example.com"
          autocomplete="off"
          spellcheck="false"
          :disabled="submitting"
          :aria-invalid="error !== ''"
          aria-describedby="host-error"
        />
        <button type="submit" :disabled="submitting">
          {{ submitting ? "正在检测…" : "检测 SSL 证书" }}
        </button>
        <p id="host-error" class="error" aria-live="polite">{{ error }}</p>
      </form>
      <FeatureGrid />
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
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.brand,
.pill,
.lead,
.error {
  margin: 0;
}

.brand {
  font-size: 14px;
  font-weight: 600;
}

.pill {
  padding: 4px 12px;
  border-radius: 999px;
  background: var(--green-bg);
  color: var(--green);
  font-size: 13px;
  font-weight: 600;
  line-height: 1.5;
  white-space: nowrap;
}

h1 {
  margin: 28px 0 10px;
  font-size: 34px;
  font-weight: 700;
  line-height: 1.2;
  letter-spacing: -0.02em;
}

.lead {
  margin-bottom: 28px;
  color: var(--muted);
  font-size: 16px;
  line-height: 1.65;
}

label {
  display: block;
  margin-bottom: 8px;
  font-size: 14px;
  font-weight: 600;
}

input,
button {
  width: 100%;
  height: 52px;
  border-radius: 999px;
  font: inherit;
  font-size: 16px;
}

input {
  padding: 0 20px;
  border: 1px solid var(--line);
  background: #f3f4f6;
  color: var(--text);
}

input::placeholder {
  color: #9ca3af;
}

input:focus-visible,
button:focus-visible {
  outline: 2px solid var(--text);
  outline-offset: 2px;
}

button {
  margin-top: 12px;
  border: 0;
  background: #111111;
  color: #ffffff;
  font-weight: 600;
  cursor: pointer;
}

button:disabled,
input:disabled {
  cursor: default;
}

.error {
  min-height: 22px;
  margin: 10px 4px 0;
  color: var(--red);
  font-size: 14px;
  line-height: 1.5;
}

@media (max-width: 719px) {
  .page {
    padding: 16px 12px 32px;
  }

  .card {
    padding: 24px 16px 20px;
  }

  h1 {
    margin-top: 22px;
    font-size: 28px;
  }
}
</style>
