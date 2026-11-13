import { readFileSync } from "node:fs";

import { describe, expect, test, vi } from "vitest";

import { checkHost } from "./api";
import critical from "./fixtures/result-critical.json";
import failed from "./fixtures/result-failed.json";
import ok from "./fixtures/result-ok.json";
import { checkedAt, headline, issuerName, matchLabel, pillTone, tableDate, tone } from "./status";

const valid = { status: "valid", label: "证书有效" };
const expiring = { status: "expiring", label: "即将过期" };

describe("status copy", () => {
  test("a comfortable certificate stays green", () => {
    const validity = { remaining_days: 72, risk_level: "ok" };
    expect(headline(validity)).toBe("72 天");
    expect(tone(valid, validity)).toBe("ok");
  });

  test("three days left is a red headline", () => {
    const validity = { remaining_days: 3, risk_level: "critical_3" };
    expect(headline(validity)).toBe("3 天");
    expect(tone(expiring, validity)).toBe("bad");
  });

  test("fifteen days uses the deeper amber", () => {
    expect(tone(expiring, { risk_level: "warning_15" })).toBe("d15");
  });

  test("expired days never display as zero", () => {
    expect(headline({ remaining_days: -1, risk_level: "expired" })).toBe("已过期 1 天");
    expect(headline({ remaining_days: 0, risk_level: "expired" })).toBe("已过期 1 天");
  });

  test("a certificate that is not valid yet has no day count", () => {
    expect(headline({ remaining_days: null, risk_level: "not_yet_valid" })).toBe("尚未生效");
  });

  test("a name mismatch stays red even with many days left", () => {
    expect(tone({ status: "mismatch", label: "域名不匹配" }, { risk_level: "ok" })).toBe("bad");
  });

  test("a complete chain pill is green", () => {
    expect(pillTone("完整")).toBe("ok");
    expect(pillTone(ok.chain.label)).toBe("ok");
  });

  test("issuer falls back to the common name", () => {
    expect(issuerName({ organization: "", common_name: "R3" })).toBe("R3");
    expect(issuerName({ organization: null, common_name: "R3" })).toBe("R3");
    expect(issuerName({ organization: null, common_name: null })).toBe("未知");
  });

  test("table dates stay on the UTC day", () => {
    expect(tableDate("2026-09-01T23:30:00Z")).toBe("2026-09-01");
    const source = readFileSync(new URL("./status.ts", import.meta.url), "utf8");
    expect(source).not.toContain("toLocaleDateString");
  });

  test("checked time is local and stops at the minute", () => {
    const rendered = checkedAt("2026-11-10T02:00:00Z");
    const date = new Date("2026-11-10T02:00:00Z");
    const pad = (value: number) => String(value).padStart(2, "0");
    const expected = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}`;
    expect(rendered).toBe(expected);
    expect(rendered).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/);
  });

  test("components do not hardcode the sample day count", () => {
    const files = [
      "status.ts",
      "api.ts",
      "views/ResultView.vue",
      "components/StatusBadge.vue",
      "components/AlertList.vue",
      "components/DetailTable.vue",
      "components/ChainList.vue",
    ];
    for (const file of files) {
      expect(readFileSync(new URL(`./${file}`, import.meta.url), "utf8"), file).not.toContain("72");
    }
  });

  test("match labels are the two capsules", () => {
    expect(matchLabel(true)).toBe("匹配");
    expect(matchLabel(false)).toBe("不匹配");
    expect(pillTone("匹配")).toBe("ok");
    expect(pillTone("不匹配")).toBe("bad");
  });
});

describe("fixtures", () => {
  test("the comfortable fixture is a complete success", () => {
    expect(ok.ok).toBe(true);
    expect(ok.validity.remaining_days).toBe(72);
    expect(ok.overall.status).toBe("valid");
    expect(ok.chain.items).toHaveLength(3);
    expect(ok.alerts).toEqual([]);
    expect(ok.certificate_type_label).toBe("DV SSL");
  });

  test("the short fixture carries one three-day reminder", () => {
    expect(critical.ok).toBe(true);
    expect(critical.validity.remaining_days).toBe(3);
    expect(critical.validity.risk_level).toBe("critical_3");
    expect(critical.overall.status).toBe("expiring");
    expect(critical.alerts).toEqual([
      { level: "critical_3", message: "剩余有效期不足 3 天，请立即续期。" },
    ]);
  });

  test("the failed fixture is only the timeout body", () => {
    expect(failed).toEqual({
      ok: false,
      host: "example.com",
      error: {
        code: "timeout",
        message: "连接超时，目标没有在 10 秒内完成 TLS 握手。",
      },
    });
  });
});

describe("checkHost", () => {
  test("400 and 429 throw the message from the body", async () => {
    const fetchMock = vi.fn(async () =>
      jsonResponse(
        {
          ok: false,
          host: "example.com;id",
          error: { code: "invalid_host", message: "请输入域名，例如 example.com。" },
        },
        400,
      ),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(checkHost("example.com;id", false)).rejects.toThrow("请输入域名，例如 example.com。");

    fetchMock.mockResolvedValueOnce(
      jsonResponse(
        {
          ok: false,
          host: "example.com",
          error: { code: "rate_limited", message: "检测过于频繁，请稍后再试。" },
        },
        429,
      ),
    );
    await expect(checkHost("example.com", false)).rejects.toThrow("检测过于频繁，请稍后再试。");
    vi.unstubAllGlobals();
  });

  test("a dropped connection throws the unavailable sentence", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    }));
    await expect(checkHost("example.com", false)).rejects.toThrow("检测服务暂时不可用。");
    vi.unstubAllGlobals();
  });

  test("200 is returned without renaming fields", async () => {
    const body = failed;
    vi.stubGlobal("fetch", vi.fn(async (url: string, init: RequestInit) => {
      expect(url).toBe("/api/v1/check");
      expect(init.method).toBe("POST");
      expect(new Headers(init.headers).get("content-type")).toBe("application/json");
      expect(JSON.parse(String(init.body))).toEqual({ host: "example.com", refresh: true });
      return jsonResponse(body, 200);
    }));
    await expect(checkHost("example.com", true)).resolves.toEqual(body);
    vi.unstubAllGlobals();
  });
});

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
