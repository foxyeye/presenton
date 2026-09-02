import { NextResponse } from "next/server";
import { authStatusForRequest } from "@/lib/server-auth-role";
import { getFastApiBaseUrl } from "@/lib/fastapi-internal";
import { hasValidLLMConfig, normalizeLLMConfig } from "@/utils/storeHelpers";
import { LLMConfig } from "@/types/llm_config";

export const dynamic = "force-dynamic";

const SECRET_FIELD = /(API_KEY|ACCESS_KEY|SECRET|TOKEN|PASSWORD)/i;

export async function GET(request: Request) {
  const auth = await authStatusForRequest(request);
  if (!auth.authenticated) {
    return NextResponse.json({ detail: "Unauthorized" }, { status: 401 });
  }
  try {
    const cookie = request.headers.get("cookie") || "";
    const response = await fetch(
      `${getFastApiBaseUrl()}/api/v1/auth/runtime-config`,
      {
        headers: cookie ? { cookie } : undefined,
        cache: "no-store",
      }
    );
    if (!response.ok) {
      return NextResponse.json(
        { configured: false, config: {} },
        { status: response.status }
      );
    }
    const full = normalizeLLMConfig(
      (await response.json()) as LLMConfig
    );
    const config = Object.fromEntries(
      Object.entries(full).map(([key, value]) => [
        key,
        SECRET_FIELD.test(key) ? (value ? "__configured__" : "") : value,
      ])
    );
    return NextResponse.json({
      configured: hasValidLLMConfig(full),
      config,
    });
  } catch {
    return NextResponse.json(
      { configured: false, config: {} },
      { status: 200 }
    );
  }
}
