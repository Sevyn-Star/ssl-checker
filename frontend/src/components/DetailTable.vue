<script setup lang="ts">
import { matchLabel, pillTone, tableDate } from "../status";
import StatusBadge from "./StatusBadge.vue";

defineProps<{
  host: string;
  issuer: string;
  notBefore: string;
  notAfter: string;
  matched: boolean;
  chainLabel: string;
  tlsVersion: string | null;
}>();
</script>

<template>
  <section>
    <h2>证书详细信息</h2>
    <dl>
      <div>
        <dt>域名</dt>
        <dd>{{ host }}</dd>
      </div>
      <div>
        <dt>颁发机构</dt>
        <dd>{{ issuer }}</dd>
      </div>
      <div>
        <dt>开始时间</dt>
        <dd>{{ tableDate(notBefore) }}</dd>
      </div>
      <div>
        <dt>到期时间</dt>
        <dd>{{ tableDate(notAfter) }}</dd>
      </div>
      <div>
        <dt>域名匹配</dt>
        <dd>
          <StatusBadge :label="matchLabel(matched)" :tone="pillTone(matchLabel(matched))" />
        </dd>
      </div>
      <div>
        <dt>证书链</dt>
        <dd>
          <StatusBadge :label="chainLabel" :tone="pillTone(chainLabel)" />
        </dd>
      </div>
      <div>
        <dt>TLS 版本</dt>
        <dd>{{ tlsVersion || "未知" }}</dd>
      </div>
    </dl>
  </section>
</template>

<style scoped>
h2 {
  margin: 32px 0 0;
  font-size: 18px;
  line-height: 1.4;
}

dl {
  margin: 4px 0 0;
}

div {
  display: grid;
  grid-template-columns: 7.5em minmax(0, 1fr);
  gap: 12px;
  align-items: center;
  padding: 13px 0;
  border-bottom: 1px solid var(--line);
}

dt,
dd {
  margin: 0;
}

dt {
  color: var(--muted);
  font-size: 14px;
}

dd {
  font-size: 15px;
  overflow-wrap: anywhere;
}
</style>
