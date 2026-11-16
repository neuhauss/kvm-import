/** Extract a concise FastAPI/Rancher diagnostic without leaking submitted secrets. */
export function apiErrorDetail(body: unknown, requestBody?: BodyInit | null): string {
  const message = errorMessage(body);

  if (!message) return '';
  let safeMessage = message.replace(/((?:password|passphrase|regcode|token|secret|private[_-]?key)\s*[:=]\s*)[^\s,;]+/gi, '$1[redacted]');

  if (typeof requestBody === 'string') {
    try {
      const values: string[] = [];
      const visit = (value: unknown, key = '') => {
        if (value && typeof value === 'object') {
          for (const [childKey, child] of Object.entries(value)) visit(child, childKey);
        } else if (typeof value === 'string' && /password|passphrase|regcode|token|secret|private[_-]?key/i.test(key) && value.length >= 4) {
          values.push(value);
        }
      };
      visit(JSON.parse(requestBody));
      for (const secret of values) safeMessage = safeMessage.split(secret).join('[redacted]');
    } catch { /* Non-JSON request bodies do not contain structured fields to redact. */ }
  }

  return safeMessage.replace(/\s+/g, ' ').trim().slice(0, 600);
}

/** Extract readable text from FastAPI validation arrays and nested error objects. */
function errorMessage(value: unknown, depth = 0): string {
  if (depth > 4 || value == null) return '';
  if (typeof value === 'string') {
    const message = value.trim();
    return /^\[(?:object|array)(?:\s|\])/i.test(message) || /^<object object>$/i.test(message) ? '' : message;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    return value.map((item) => {
      if (item && typeof item === 'object' && !Array.isArray(item)) {
        const row = item as Record<string, unknown>;
        const location = Array.isArray(row.loc) ? row.loc.filter((part) => part !== 'body' && part !== 'query').map(String).join('.') : '';
        const issue = errorMessage(row.msg ?? row.message ?? row.detail ?? row.error, depth + 1);
        return [location, issue].filter(Boolean).join(': ');
      }
      return errorMessage(item, depth + 1);
    }).filter(Boolean).join('; ');
  }
  if (typeof value === 'object') {
    const object = value as Record<string, unknown>;
    for (const key of ['detail', 'message', 'msg', 'error', 'reason', 'description']) {
      const message = errorMessage(object[key], depth + 1);
      if (message) return message;
    }
    return '';
  }
  return '';
}
