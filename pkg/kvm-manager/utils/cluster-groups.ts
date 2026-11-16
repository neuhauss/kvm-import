export function validClusterGroupSelection(resourceId: string, children: string[]): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(resourceId)
    && children.length >= 1
    && children.length <= 128
    && children.every((child) => /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(child))
    && new Set(children).size === children.length;
}

export function toggleClusterGroupMember(children: string[], id: string, checked: boolean): string[] {
  const next = children.filter((item) => item !== id);
  if (checked) next.push(id);
  return next;
}

export function moveClusterGroupMember(children: string[], index: number, delta: number): string[] {
  const target = index + delta;
  if (!Number.isInteger(index) || !Number.isInteger(delta) || index < 0 || index >= children.length || target < 0 || target >= children.length) return [...children];
  const next = [...children];
  [next[index], next[target]] = [next[target], next[index]];
  return next;
}
