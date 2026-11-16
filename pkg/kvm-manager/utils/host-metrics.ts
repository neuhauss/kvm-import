/** Return whether the host's embedded metrics sample is old enough to refresh. */
export function hostMetricsNeedRefresh(updatedAt: string, now = Date.now(), intervalMs = 30_000): boolean {
  if (!updatedAt) return true;
  const sampledAt = Date.parse(updatedAt);
  return !Number.isFinite(sampledAt) || now - sampledAt >= intervalMs;
}
