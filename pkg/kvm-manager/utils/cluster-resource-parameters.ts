export type ResourceParameterRow = { key: string; value: string };

export type ResourceParameterParseResult =
  | { ok: true; parameters: Record<string, string> }
  | { ok: false; reason: 'invalid_row' | 'duplicate_key' | 'too_many'; row?: number };

/** Convert the guided resource form into the Pacemaker parameters payload. */
export function resourceParametersFromRows(rows: readonly ResourceParameterRow[]): ResourceParameterParseResult {
  const parameters: Array<[string, string]> = [];
  const seen = new Set<string>();

  for (const [index, row] of rows.entries()) {
    const key = row.key.trim();
    const value = row.value;
    if (!key && !value) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(key) || !value || value.length > 2048 || /[\x00-\x1f\x7f]/.test(value)) {
      return { ok: false, reason: 'invalid_row', row: index + 1 };
    }
    if (seen.has(key)) return { ok: false, reason: 'duplicate_key', row: index + 1 };
    seen.add(key);
    parameters.push([key, value]);
    if (parameters.length > 40) return { ok: false, reason: 'too_many' };
  }

  return { ok: true, parameters: Object.fromEntries(parameters) };
}
