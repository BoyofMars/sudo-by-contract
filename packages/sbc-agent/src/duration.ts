// "90s", "10m", "1h", "1h30m", or a plain number of seconds.

const UNIT: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };

export function parseDuration(input: string | number): number {
  if (typeof input === "number") {
    if (!Number.isInteger(input) || input <= 0) throw new Error(`invalid duration ${input}`);
    return input;
  }
  const s = input.trim().toLowerCase();
  if (/^\d+$/.test(s)) return parseDuration(Number(s));
  const re = /(\d+)\s*([smhd])/g;
  let total = 0;
  let consumed = 0;
  for (const m of s.matchAll(re)) {
    total += Number(m[1]) * UNIT[m[2]];
    consumed += m[0].length;
  }
  if (!total || consumed !== s.replace(/\s+/g, "").length) {
    throw new Error(`invalid duration "${input}" (use e.g. 90s, 10m, 1h)`);
  }
  return total;
}
