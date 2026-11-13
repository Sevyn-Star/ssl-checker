import type { CheckResult } from "./types";

const UNAVAILABLE = "检测服务暂时不可用。";

export async function checkHost(host: string, refresh: boolean): Promise<CheckResult> {
  let response: Response;
  try {
    response = await fetch("/api/v1/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ host, refresh }),
    });
  } catch {
    throw new Error(UNAVAILABLE);
  }

  if (response.status === 400 || response.status === 429) {
    throw new Error(await readMessage(response));
  }
  if (!response.ok) {
    throw new Error(UNAVAILABLE);
  }
  try {
    return await response.json();
  } catch {
    throw new Error(UNAVAILABLE);
  }
}

async function readMessage(response: Response): Promise<string> {
  try {
    const body = await response.json();
    const nested = body?.error?.message;
    if (typeof nested === "string" && nested !== "") return nested;
    if (typeof body?.message === "string" && body.message !== "") return body.message;
  } catch {
    // 没有可读正文时用统一的一句。
  }
  return UNAVAILABLE;
}
