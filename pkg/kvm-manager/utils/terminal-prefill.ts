/** Return an editable single-line shell command; never include Enter/newline. */
export function terminalPrefillCommand(value: string): string | null {
  if (!value || value.length > 2000 || /[\r\n\0]/.test(value)) return null;
  return value;
}
