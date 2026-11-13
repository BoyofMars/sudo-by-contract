// The demo agent is also the demo's narrator: calm, legible, honest output.

const color = !process.env.NO_COLOR && (process.stdout.isTTY || process.env.FORCE_COLOR === "1");
const sgr = (code: string) => (s: string) => (color ? `\x1b[${code}m${s}\x1b[0m` : s);

export const style = {
  bold: sgr("1"),
  dim: sgr("2"),
  red: sgr("31"),
  green: sgr("32"),
  yellow: sgr("33"),
  cyan: sgr("36"),
  inverse: sgr("7"),
};

let write: (s: string) => void = (s) => void process.stdout.write(s);
/** Redirect the narration (tests silence it this way, without touching stdout). */
export function setNarrationOutput(w: (s: string) => void) {
  write = w;
}

export const say = (s = "") => write(s + "\n");

export function act(n: number, title: string, subtitle: string) {
  say();
  say(style.dim("─".repeat(72)));
  say(`${style.bold(`ACT ${n}`)}  ${style.bold(title)}`);
  say(style.dim(subtitle));
  say(style.dim("─".repeat(72)));
}

export function step(label: string, text: string) {
  say(`${style.dim(label.padEnd(10))} ${text}`);
}

export function thought(text: string) {
  say(`${style.cyan("agent")}      ${style.cyan("“" + text + "”")}`);
}

export function ok(text: string) {
  say(`${style.green("  ✓")} ${text}`);
}

export function fail(text: string) {
  say(`${style.red("  ✕")} ${text}`);
}

export function wait(text: string) {
  say(`${style.yellow("  ○")} ${text}`);
}

export function indent(text: string, prefix = "    │ ") {
  for (const line of text.replace(/\s+$/, "").split(/\r?\n/)) if (line.trim()) say(style.dim(prefix) + line);
}

export function command(cmd: string) {
  say();
  say(`  ${style.dim("$")} ${style.bold(cmd)}`);
}

export function verdict(expected: boolean, text: string) {
  say(`    ${expected ? style.dim("→ as expected:") : style.red(style.bold("→ UNEXPECTED:"))} ${text}`);
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
