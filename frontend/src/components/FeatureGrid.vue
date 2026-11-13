<script setup lang="ts">
const cards = [
  { key: "expiry", title: "证书有效期", text: "签发时间、到期时间、剩余天数" },
  { key: "status", title: "证书状态", text: "有效、过期、即将过期" },
  { key: "issuer", title: "颁发机构", text: "Issuer、CA 机构" },
  { key: "chain", title: "证书链", text: "根证书、中间证书、链完整性" },
];
</script>

<template>
  <ul class="grid">
    <li v-for="card in cards" :key="card.key">
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <template v-if="card.key === 'expiry'">
          <rect x="4" y="5" width="16" height="15" rx="2" />
          <path d="M8 3.5v3M16 3.5v3M4 10h16" />
        </template>
        <template v-else-if="card.key === 'status'">
          <circle cx="12" cy="12" r="8" />
          <path d="M8.5 12.2 10.8 14.5 15.5 9.5" />
        </template>
        <template v-else-if="card.key === 'issuer'">
          <path d="M4 20V9l8-4 8 4v11" />
          <path d="M9 20v-5h6v5M4 20h16" />
        </template>
        <template v-else>
          <path d="M9.5 14.5 7.8 16.2a3 3 0 0 1-4.2-4.2l1.7-1.7" />
          <path d="M14.5 9.5 16.2 7.8a3 3 0 0 1 4.2 4.2l-1.7 1.7" />
          <path d="M9 15l6-6" />
        </template>
      </svg>
      <h2>{{ card.title }}</h2>
      <p>{{ card.text }}</p>
    </li>
  </ul>
</template>

<style scoped>
.grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
  margin: 20px 0 0;
  padding: 0;
  list-style: none;
}

li {
  padding: 16px 14px 18px;
  border: 1px solid var(--line);
  border-radius: 16px;
  background: var(--card);
}

svg {
  display: block;
  width: 22px;
  height: 22px;
  fill: none;
  stroke: currentColor;
  stroke-width: 1.7;
  stroke-linecap: round;
  stroke-linejoin: round;
}

h2 {
  margin: 12px 0 6px;
  font-size: 15px;
  font-weight: 600;
  line-height: 1.3;
}

p {
  margin: 0;
  color: var(--muted);
  font-size: 13px;
  line-height: 1.5;
}

@media (max-width: 719px) {
  .grid {
    grid-template-columns: 1fr;
  }
}
</style>
