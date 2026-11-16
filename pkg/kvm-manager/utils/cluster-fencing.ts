import { resourceParametersFromRows, type ResourceParameterRow } from './cluster-resource-parameters.ts';
import { validateClusterMonitorOperations } from './cluster-monitor-operations.ts';

export type FencingDeviceDraft = {
  mode?: 'create' | 'edit';
  resource_id: string;
  agent: string;
  target_node: string;
  parameters: ResourceParameterRow[];
  monitor_interval: string;
  monitor_timeout: string;
};

export type FencingParameterEditRow = ResourceParameterRow & { existing?: boolean; remove?: boolean };

export type FencingDeviceValidation =
  | { ok: true; resource_id: string; agent: string; target_node: string; parameters: Record<string, string>; monitor_interval: string; monitor_timeout: string }
  | { ok: false; reason: 'invalid_id' | 'invalid_agent' | 'invalid_target' | 'invalid_parameters' | 'reserved_parameter' | 'invalid_monitor' };

const ID = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const AGENT = /^stonith:(?:[A-Za-z0-9_.+-]+\/)?[A-Za-z0-9_.+-]+$/;

/** Validate an extension-created STONITH primitive before it enters the reviewed mutation queue. */
export function validateFencingDeviceDraft(draft: FencingDeviceDraft, clusterNodes: readonly string[]): FencingDeviceValidation {
  const resource_id = draft.resource_id.trim();
  if (!ID.test(resource_id)) return { ok: false, reason: 'invalid_id' };
  const agent = draft.agent.trim();
  if (!AGENT.test(agent)) return { ok: false, reason: 'invalid_agent' };
  const target_node = draft.target_node.trim();
  if (!target_node || !clusterNodes.includes(target_node)) return { ok: false, reason: 'invalid_target' };
  const parsed = resourceParametersFromRows(draft.parameters);
  if (!parsed.ok) return { ok: false, reason: 'invalid_parameters' };
  if (Object.keys(parsed.parameters).some((key) => ['pcmk_host_list', 'pcmk_host_map'].includes(key.toLowerCase()))) {
    return { ok: false, reason: 'reserved_parameter' };
  }
  const monitor = validateClusterMonitorOperations([{ interval: draft.monitor_interval, role: '', timeout: draft.monitor_timeout }]);
  if (!monitor.ok) return { ok: false, reason: 'invalid_monitor' };
  return { ok: true, resource_id, agent, target_node, parameters: parsed.parameters, monitor_interval: monitor.operations[0].interval, monitor_timeout: monitor.operations[0].timeout || '' };
}

/** Keep hardware credentials masked by default when the parameter name is credential-like. */
export function isSensitiveFencingParameter(name: string): boolean {
  return /(?:pass(?:word|wd)?|secret|token|credential|private.?key|api.?key)/i.test(name);
}

/** Validate edits without ever requiring existing fencing values to be read back from CIB. */
export function validateFencingParameterEdits(rows: readonly FencingParameterEditRow[]):
  | { ok: true; parameters: Record<string, string>; parameter_removals: string[] }
  | { ok: false; reason: 'invalid_parameters' | 'reserved_parameter' | 'no_changes' } {
  const parameters: Record<string, string> = {};
  const parameter_removals: string[] = [];
  const seen = new Set<string>();
  for (const row of rows) {
    const key = row.key.trim();
    const value = row.value;
    if (!key && !value) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(key) || value.length > 2048 || /[\x00-\x1f\x7f]/.test(value)) {
      return { ok: false, reason: 'invalid_parameters' };
    }
    if (seen.has(key)) return { ok: false, reason: 'invalid_parameters' };
    seen.add(key);
    if (['pcmk_host_list', 'pcmk_host_map'].includes(key.toLowerCase())) return { ok: false, reason: 'reserved_parameter' };
    if (row.existing) {
      if (row.remove) {
        if (value) return { ok: false, reason: 'invalid_parameters' };
        parameter_removals.push(key);
      } else if (value) parameters[key] = value;
      // Empty value on an existing row means retain its currently stored value.
    } else {
      if (!value) return { ok: false, reason: 'invalid_parameters' };
      parameters[key] = value;
    }
  }
  if (!Object.keys(parameters).length && !parameter_removals.length) return { ok: false, reason: 'no_changes' };
  return { ok: true, parameters, parameter_removals };
}
