/** Extract a concise FastAPI/Rancher diagnostic without leaking submitted secrets. */
export function apiErrorDetail(body: unknown, requestBody?: BodyInit | null): string {
  const payload = body as any;
  const detail = payload?.detail ?? payload?.message ?? payload?.error;
  let message = '';

  if (typeof detail === 'string') message = detail;
  else if (Array.isArray(detail)) {
    message = detail.map((item: any) => {
      const location = Array.isArray(item?.loc) ? item.loc.filter((part: unknown) => part !== 'body' && part !== 'query').join('.') : '';
      const issue = typeof item?.msg === 'string' ? item.msg : '';
      return [location, issue].filter(Boolean).join(': ');
    }).filter(Boolean).join('; ');
  }

  if (!message) return '';
  message = message.replace(/((?:password|passphrase|regcode|token|secret|private[_-]?key)\s*[:=]\s*)[^\s,;]+/gi, '$1[redacted]');

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
      for (const secret of values) message = message.split(secret).join('[redacted]');
    } catch { /* Non-JSON request bodies do not contain structured fields to redact. */ }
  }

  return message.replace(/\s+/g, ' ').trim().slice(0, 600);
}
