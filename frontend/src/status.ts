import type { Overall, Party, Validity } from "./types";

export type Tone = "ok" | "d30" | "d15" | "d7" | "bad";

const OK_PILLS = new Set(["匹配", "完整", "有效", "可信"]);

export function headline(validity: Pick<Validity, "remaining_days" | "risk_level">): string {
  if (validity.risk_level === "not_yet_valid") return "尚未生效";
  if (validity.risk_level === "expired") {
    const days = validity.remaining_days ?? 0;
    return `已过期 ${Math.max(1, -days)} 天`;
  }
  return `${validity.remaining_days} 天`;
}

export function tone(overall: Pick<Overall, "status">, validity: Pick<Validity, "risk_level">): Tone {
  if (
    overall.status === "not_yet_valid" ||
    overall.status === "expired" ||
    overall.status === "mismatch" ||
    overall.status === "chain_error"
  ) {
    return "bad";
  }
  if (validity.risk_level === "ok") return "ok";
  if (validity.risk_level === "notice_30") return "d30";
  if (validity.risk_level === "warning_15") return "d15";
  if (validity.risk_level === "warning_7") return "d7";
  if (validity.risk_level === "critical_3") return "bad";
  return "bad";
}

export function issuerName(issuer: Pick<Party, "organization" | "common_name">): string {
  if (issuer.organization) return issuer.organization;
  if (issuer.common_name) return issuer.common_name;
  return "未知";
}

export function tableDate(iso: string): string {
  const date = new Date(iso);
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
}

export function checkedAt(iso: string): string {
  const date = new Date(iso);
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

export function matchLabel(matched: boolean): string {
  return matched ? "匹配" : "不匹配";
}

export function pillTone(kind: string): "ok" | "bad" {
  return OK_PILLS.has(kind) ? "ok" : "bad";
}

function pad(value: number): string {
  return String(value).padStart(2, "0");
}
