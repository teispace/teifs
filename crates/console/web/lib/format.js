// How numbers and dates read on the page.

const UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];

/** A size in bytes for people: `1.5 MiB`. */
export function bytes(n) {
  const value = Number(n);
  if (!Number.isFinite(value) || value < 0) return "";
  let unit = 0;
  let size = value;
  while (size >= 1024 && unit < UNITS.length - 1) {
    size /= 1024;
    unit++;
  }
  const digits = unit === 0 || size >= 100 ? 0 : size >= 10 ? 1 : 2;
  return `${size.toFixed(digits)} ${UNITS[unit]}`;
}

/** An ISO 8601 time as a local date and time, or "" when it isn't one. */
export function dateTime(iso, locale) {
  if (!iso) return "";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
}

/** A duration in seconds for people: `3 h 5 min`, `42 s`. */
export function duration(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);
  if (days) return hours ? `${days} d ${hours} h` : `${days} d`;
  if (hours) return minutes ? `${hours} h ${minutes} min` : `${hours} h`;
  if (minutes) return `${minutes} min`;
  return `${s} s`;
}
