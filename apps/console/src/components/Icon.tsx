// 16px stroke icons. Deliberately no padlocks: boundaries and windows instead.

const P: Record<string, string> = {
  overview: "M2.5 2.5h4.5v4.5H2.5zM9 2.5h4.5v7H9zM2.5 9h4.5v4.5H2.5zM9 11.5h4.5v2H9z",
  requests: "M3 3.5h10M3 8h10M3 12.5h6",
  active: "M2 8h2.5M11.5 8H14M4.5 4.5v7M11.5 4.5v7M6.5 8h3",
  agents: "M8 2.5l5 2.75v5.5L8 13.5l-5-2.75v-5.5zM8 8v5.5M8 8l5-2.75M8 8L3 5.25",
  resources: "M2.5 3h11v4h-11zM2.5 9h11v4h-11zM5 5h.01M5 11h.01",
  policies: "M8 2l5 2v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4z",
  audit: "M4 2.5h8v11H4zM6 5.5h4M6 8h4M6 10.5h2",
  settings: "M3 4.5h6M11.5 4.5H13M3 11.5h1.5M7 11.5h6M9 3v3M5 10v3",
  check: "M3.5 8.5l3 3 6-7",
  x: "M4 4l8 8M12 4l-8 8",
  dot: "M8 8h.01",
  circle: "M8 3.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9z",
  arrow: "M3 8h10M9 4l4 4-4 4",
  back: "M13 8H3M7 4L3 8l4 4",
  copy: "M5.5 5.5h7v7h-7zM3.5 10.5v-7h7",
  external: "M9 3h4v4M13 3L7.5 8.5M11 9.5V13H3V5h3.5",
  chevron: "M6 4l4 4-4 4",
  down: "M4 6l4 4 4-4",
  menu: "M2.5 4h11M2.5 8h11M2.5 12h11",
  sun: "M8 5a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.4 3.4l1 1M11.6 11.6l1 1M3.4 12.6l1-1M11.6 4.4l1-1",
  moon: "M13 9.5A5.5 5.5 0 0 1 6.5 3a5.5 5.5 0 1 0 6.5 6.5z",
  plus: "M8 3v10M3 8h10",
  key: "M10 2.5a3.5 3.5 0 1 1-3.3 4.6L2.5 11.3V13.5H5v-1.5h1.5v-1.5l1.4-1.4A3.5 3.5 0 0 1 10 2.5z",
  clock: "M8 2.5a5.5 5.5 0 1 0 0 11 5.5 5.5 0 0 0 0-11zM8 5v3l2 1.5",
  terminal: "M2.5 3h11v10h-11zM5 6.5l2 1.5-2 1.5M8.5 10H11",
  alert: "M8 2.5l6 10.5H2zM8 6.5v3M8 11.5h.01",
  shield: "M8 2l5 2v4c0 3-2.2 5-5 6-2.8-1-5-3-5-6V4z",
  link: "M6.5 9.5l3-3M7 4.5l1-1a2.5 2.5 0 0 1 3.5 3.5l-1 1M9 11.5l-1 1A2.5 2.5 0 0 1 4.5 9l1-1",
  more: "M3.5 8h.01M8 8h.01M12.5 8h.01",
  bell: "M4 11V7a4 4 0 0 1 8 0v4l1 1.5H3zM6.5 13.5a1.5 1.5 0 0 0 3 0",
  refresh: "M13 8a5 5 0 1 1-1.5-3.5M13 2.5v3h-3",
};

export function Icon({ name, size = 16, className, title }: { name: keyof typeof P | string; size?: number; className?: string; title?: string }) {
  const d = P[name] ?? P.dot;
  return (
    <svg
      className={"icon " + (className ?? "")}
      width={size}
      height={size}
      viewBox="0 0 16 16"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden={title ? undefined : true}
      role={title ? "img" : undefined}
    >
      {title ? <title>{title}</title> : null}
      <path d={d} />
    </svg>
  );
}

/** The mark: a privilege (bar) held inside a bounded window (brackets). */
export function Mark({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden className="mark">
      <path d="M7 4H4v16h3" stroke="currentColor" strokeWidth="2" strokeLinecap="square" />
      <path d="M17 4h3v16h-3" stroke="currentColor" strokeWidth="2" strokeLinecap="square" />
      <rect x="9" y="10.5" width="6" height="3" fill="var(--active)" />
    </svg>
  );
}
