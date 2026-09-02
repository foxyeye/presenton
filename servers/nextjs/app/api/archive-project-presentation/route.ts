import { NextRequest, NextResponse } from "next/server";
import fs from "fs/promises";
import path from "path";

import { bundledExportPackageAvailable, runBundledPresentationExport } from "@/lib/run-bundled-presentation-export";
import { authStatusForRequest } from "@/lib/server-auth-role";

const ARCHIVE_COOKIE = "presenton_opc_archive_context";

export async function POST(req: NextRequest) {
  const auth = await authStatusForRequest(req);
  if (!auth.authenticated) return NextResponse.json({ detail: "Unauthorized" }, { status: 401 });
  const contextToken = req.cookies.get(ARCHIVE_COOKIE)?.value;
  if (!contextToken) return NextResponse.json({ error: "This presentation was not opened from an OPC project." }, { status: 409 });
  const body = await req.json().catch(() => null) as { id?: unknown; title?: unknown } | null;
  if (!body || typeof body.id !== "string" || !body.id.trim()) return NextResponse.json({ error: "Missing Presentation ID" }, { status: 400 });
  const apiURL = process.env.OPC_API_INTERNAL_URL?.trim();
  if (!apiURL) return NextResponse.json({ error: "OPC archive service is not configured." }, { status: 503 });
  try {
    if (!(await bundledExportPackageAvailable())) throw new Error("presentation-export runtime is not available");
    const result = await runBundledPresentationExport({ format: "pptx", presentationId: body.id.trim(), title: typeof body.title === "string" ? body.title : undefined, cookieHeader: req.headers.get("cookie") ?? "" });
    const data = await fs.readFile(result.path);
    const bytes = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
    const form = new FormData();
    form.append("file", new Blob([bytes], { type: "application/vnd.openxmlformats-officedocument.presentationml.presentation" }), path.basename(result.path));
    const response = await fetch(`${apiURL.replace(/\/$/, "")}/api/v1/integrations/presenton/project-export`, { method: "POST", headers: { Authorization: `Bearer ${contextToken}` }, body: form });
    if (!response.ok) throw new Error(`OPC archive service returned ${response.status}`);
    return NextResponse.json({ success: true, ...(await response.json()) });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[archive-project-presentation]", message);
    return NextResponse.json({ error: message, success: false }, { status: 500 });
  }
}
