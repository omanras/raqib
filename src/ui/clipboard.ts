// Export without a network: copy to the clipboard (with a manual fallback
// where the clipboard API is refused, e.g. a sandboxed frame), and a
// download through a local object URL (which some sandboxes make inert;
// copying always works).

/** Copy text; false when the browser refused and the caller must show it for manual copying. */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the selection fallback */
  }
  try {
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    const ok = document.execCommand("copy");
    area.remove();
    return ok;
  } catch {
    return false;
  }
}

/** Offer the text as a file download. */
export function downloadText(name: string, text: string, type = "text/plain"): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${type};charset=utf-8` }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

/** The media type a file is downloaded with. */
export function mediaType(name: string): string {
  return name.endsWith(".csv") ? "text/csv" : name.endsWith(".yml") ? "application/yaml" : "text/plain";
}
