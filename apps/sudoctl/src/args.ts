// Argument parsing: positionals, `--flag value`, `--flag=value`, repeated
// flags, boolean flags, and everything after `--` kept verbatim.

export const BOOLEAN_FLAGS = new Set(["json", "wait", "no-wait", "admin", "help", "h", "yes", "submit-anyway", "verbose", "all"]);

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export class Args {
  positionals: string[];
  rest: string[];
  private values: Map<string, string[]>;
  private bools: Set<string>;

  constructor(positionals: string[], rest: string[], values: Map<string, string[]>, bools: Set<string>) {
    this.positionals = positionals;
    this.rest = rest;
    this.values = values;
    this.bools = bools;
  }

  flag(name: string): string | undefined {
    const v = this.values.get(name);
    return v ? v[v.length - 1] : undefined;
  }

  required(name: string, hint = ""): string {
    const v = this.flag(name);
    if (v === undefined || v === "") throw new UsageError(`--${name} is required${hint ? ` (${hint})` : ""}`);
    return v;
  }

  all(name: string): string[] {
    return this.values.get(name) ?? [];
  }

  bool(name: string): boolean {
    return this.bools.has(name);
  }

  pos(i: number, name?: string): string {
    const v = this.positionals[i];
    if (v === undefined && name) throw new UsageError(`missing <${name}>`);
    return v;
  }

  int(name: string): number | undefined {
    const v = this.flag(name);
    if (v === undefined) return undefined;
    if (!/^\d+$/.test(v)) throw new UsageError(`--${name} must be a whole number`);
    return Number(v);
  }
}

export function parseArgs(argv: string[], booleans: Set<string> = BOOLEAN_FLAGS): Args {
  const positionals: string[] = [];
  const values = new Map<string, string[]>();
  const bools = new Set<string>();
  let rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--") {
      rest = argv.slice(i + 1);
      break;
    }
    if (a.startsWith("--") || (a.startsWith("-") && a.length === 2 && !/\d/.test(a[1]))) {
      const body = a.replace(/^--?/, "");
      const eq = body.indexOf("=");
      const name = eq >= 0 ? body.slice(0, eq) : body;
      if (booleans.has(name)) {
        if (eq >= 0) throw new UsageError(`--${name} does not take a value`);
        bools.add(name === "h" ? "help" : name);
        continue;
      }
      let value: string;
      if (eq >= 0) value = body.slice(eq + 1);
      else {
        if (i + 1 >= argv.length) throw new UsageError(`--${name} needs a value`);
        value = argv[++i];
      }
      values.set(name, [...(values.get(name) ?? []), value]);
      continue;
    }
    positionals.push(a);
  }
  return new Args(positionals, rest, values, bools);
}

/** Longest known command path that prefixes the positionals. */
export function resolveCommand(positionals: string[], commands: string[]): { command: string | null; args: string[] } {
  let best: string | null = null;
  let len = 0;
  for (const c of commands) {
    const parts = c.split(" ");
    if (parts.length > len && parts.every((p, i) => positionals[i] === p)) {
      best = c;
      len = parts.length;
    }
  }
  return { command: best, args: positionals.slice(len) };
}
