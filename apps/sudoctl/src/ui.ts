// Terminal presentation: restrained color, aligned tables, explicit marks.

const useColor = !process.env.NO_COLOR && (process.stdout.isTTY ?? false);
const wrap = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);

export const c = {
  bold: wrap("1"),
  dim: wrap("2"),
  red: wrap("31"),
  green: wrap("32"),
  yellow: wrap("33"),
  blue: wrap("34"),
  cyan: wrap("36"),
};

export const mark = {
  ok: c.green("✓"),
  fail: c.red("✕"),
  wait: c.yellow("○"),
  info: c.dim("·"),
};

const visible = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "").length;

export function table(headers: string[], rows: string[][]): string {
  const widths = headers.map((h, i) => Math.max(visible(h), ...rows.map((r) => visible(r[i] ?? ""))));
  const line = (cells: string[]) => cells.map((cell, i) => cell + " ".repeat(widths[i] - visible(cell))).join("  ").trimEnd();
  return [c.dim(line(headers)), ...rows.map(line)].join("\n");
}

export function time(ms: number | null | undefined): string {
  if (!ms) return "—";
  const d = new Date(ms);
  return d.toISOString().replace("T", " ").slice(0, 19) + "Z";
}

export function clock(ms: number): string {
  return new Date(ms).toISOString().slice(11, 19) + "Z";
}

export function ago(ms: number | null | undefined, now = Date.now()): string {
  if (!ms) return "never";
  const s = Math.round((now - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function stateColor(state: string): string {
  switch (state) {
    case "Active":
      return c.green(state);
    case "PendingApproval":
    case "Signing":
      return c.yellow(state);
    case "Revoked":
    case "Denied":
    case "Rejected":
    case "Failed":
      return c.red(state);
    default:
      return c.dim(state);
  }
}
