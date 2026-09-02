import { NextRequest, NextResponse } from "next/server";
import { authStatusForRequest } from "@/lib/server-auth-role";

const ARCHIVE_COOKIE = "presenton_opc_archive_context";

export async function POST(req: NextRequest) {
  const auth = await authStatusForRequest(req);
  if (!auth.authenticated) return NextResponse.json({ detail: "Unauthorized" }, { status: 401 });
  const contextToken = req.cookies.get(ARCHIVE_COOKIE)?.value;
  if (!contextToken) return NextResponse.json({ skipped: true });
  const body = await req.json().catch(() => null) as { presentonId?: unknown } | null;
  if (!body || typeof body.presentonId !== "string" || !body.presentonId.trim()) return NextResponse.json({ error: "Missing Presenton presentation ID" }, { status: 400 });
  const apiURL = process.env.OPC_API_INTERNAL_URL?.trim();
  if (!apiURL) return NextResponse.json({ error: "OPC integration is not configured" }, { status: 503 });
  const response = await fetch(`${apiURL.replace(/\/$/, "")}/api/v1/integrations/presenton/project-presentation`, {
    method: "POST",
    headers: { Authorization: `Bearer ${contextToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ presentonId: body.presentonId.trim() }),
  });
  if (!response.ok) return NextResponse.json({ error: "Unable to bind this presentation to its OPC project" }, { status: response.status });
  return NextResponse.json(await response.json());
}
