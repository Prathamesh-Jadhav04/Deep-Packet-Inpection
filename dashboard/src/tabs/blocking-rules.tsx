'use client';

import { useState, useMemo, useEffect } from 'react';
import { useDPIRules } from '@/hooks/useDPIRules';
import { useDPIStats } from '@/hooks/useDPIStats';
import { Shield, Plus, Trash2, Search, FileDown, AlertCircle, CheckCircle } from 'lucide-react';
import type { RuleType } from '@/types/dpi';

const detectRuleType = (value: string): RuleType => {
  const clean = value.trim().toLowerCase();
  if (!clean) return 'ip';

  // 1. Check if it's an IP address (IPv4 or IPv6)
  const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}$/;
  if (ipRegex.test(clean)) {
    return 'ip';
  }

  // 2. Check if it's a known application signature
  const knownApps = [
    'unknown', 'http', 'https', 'dns', 'tls', 'quic',
    'google', 'facebook', 'youtube', 'twitter', 'x', 'twitter/x', 'instagram',
    'netflix', 'amazon', 'microsoft', 'apple', 'whatsapp',
    'telegram', 'tiktok', 'spotify', 'zoom', 'discord',
    'github', 'cloudflare'
  ];
  if (knownApps.includes(clean)) {
    return 'app';
  }

  // 3. Otherwise, if it has dots/extensions or just text, default to domain
  return 'domain';
};

export default function BlockingRulesTab() {
  const { stats, mutate } = useDPIStats();
  const { addRule, removeRule, isLoading, error: apiError } = useDPIRules();
  
  const [ruleType, setRuleType] = useState<RuleType>('ip');
  const [ruleValue, setRuleValue] = useState('');
  const [filterText, setFilterText] = useState('');
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Extract rules snapshot from current stats
  const rules = useMemo(() => {
    return stats?.rules || { ips: [], apps: [], domains: [] };
  }, [stats?.rules]);

  // Clean form status message after 4s
  useEffect(() => {
    if (actionMessage) {
      const timer = setTimeout(() => setActionMessage(null), 4000);
      return () => clearTimeout(timer);
    }
  }, [actionMessage]);

  // Handle adding rule
  const handleAddRule = async (e: React.FormEvent) => {
    e.preventDefault();
    const value = ruleValue.trim();
    if (!value) return;

    const detectedType = detectRuleType(value);

    // Direct duplicates checking
    let isDuplicate = false;
    if (detectedType === 'ip' && rules.ips.includes(value)) isDuplicate = true;
    if (detectedType === 'app' && rules.apps.includes(value)) isDuplicate = true;
    if (detectedType === 'domain' && rules.domains.includes(value)) isDuplicate = true;

    if (isDuplicate) {
      setActionMessage({ type: 'error', text: `Rule already exists for ${detectedType}: ${value}` });
      return;
    }

    const res = await addRule(detectedType, value);
    if (res.ok) {
      setActionMessage({ type: 'success', text: `Successfully blocked ${detectedType}: ${value}` });
      setRuleValue('');
      mutate(); // Refresh stats rules snapshot
    } else {
      setActionMessage({ type: 'error', text: res.message || 'Failed to add rule' });
    }
  };

  // Handle deleting rule
  const handleDeleteRule = async (type: RuleType, value: string) => {
    if (!confirm(`Are you sure you want to remove the block rule for ${type}: "${value}"?`)) {
      return;
    }
    const res = await removeRule(type, value);
    if (res.ok) {
      setActionMessage({ type: 'success', text: `Unblocked ${type}: ${value}` });
      mutate(); // Refresh rules
    } else {
      setActionMessage({ type: 'error', text: res.message || 'Failed to delete rule' });
    }
  };

  // Export current rules snapshot as JSON file
  const handleExportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rules, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `dpi_blocking_rules_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Filter rules list based on search term
  const filteredRulesList = useMemo(() => {
    const list: { type: RuleType; value: string }[] = [];
    rules.ips.forEach(val => list.push({ type: 'ip', value: val }));
    rules.apps.forEach(val => list.push({ type: 'app', value: val }));
    rules.domains.forEach(val => list.push({ type: 'domain', value: val }));

    if (!filterText.trim()) return list;
    const query = filterText.toLowerCase();
    return list.filter(r => r.type.includes(query) || r.value.toLowerCase().includes(query));
  }, [rules, filterText]);

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between border-b border-[var(--border)] pb-4">
        <div>
          <h2 className="text-display-sm">Active Blocking Rules</h2>
          <p className="text-caption text-[var(--text-muted)] mt-1">
            Manage traffic blocking rules applied in real-time by the DPI Engine filtering workers.
          </p>
        </div>
        <button
          onClick={handleExportJSON}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-caption font-medium border border-[var(--border)] bg-[var(--panel-soft)] hover:bg-[var(--panel-hover)] text-[var(--text-secondary)] transition-colors cursor-pointer"
        >
          <FileDown className="w-3.5 h-3.5" />
          <span>Export rules</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Create Rule Panel */}
        <div className="space-y-4">
          <div className="dpi-card space-y-4">
            <div className="flex items-center gap-2 text-body-sm font-semibold text-[var(--text)]">
              <Shield className="w-4 h-4 text-[var(--accent-red)]" />
              <span>Block New Traffic</span>
            </div>

            <form onSubmit={handleAddRule} className="space-y-3.5">
              <div className="flex flex-col gap-1.5">
                <label className="text-caption text-[var(--text-secondary)] font-medium">Filter Category</label>
                <div className="grid grid-cols-3 gap-1.5">
                  {(['ip', 'app', 'domain'] as const).map(t => (
                    <button
                      key={t}
                      type="button"
                      onClick={() => setRuleType(t)}
                      className={`py-1.5 rounded-md text-caption font-semibold border transition-all cursor-pointer ${
                        ruleType === t
                          ? 'border-[var(--accent-red)] bg-[var(--accent-red-soft)] text-[var(--accent-red)]'
                          : 'border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text-secondary)] hover:text-[var(--text)]'
                      }`}
                    >
                      {t === 'ip' ? 'IP Address' : t === 'app' ? 'Application' : 'Domain'}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex flex-col gap-1.5">
                <label className="text-caption text-[var(--text-secondary)] font-medium">
                  {ruleType === 'ip'
                    ? 'Target IP Address'
                    : ruleType === 'app'
                    ? 'App Name signature'
                    : 'Domain name substring'}
                </label>
                <input
                  type="text"
                  value={ruleValue}
                  onChange={(e) => {
                    const val = e.target.value;
                    setRuleValue(val);
                    setRuleType(detectRuleType(val));
                  }}
                  className="px-3 py-1.5 rounded-md text-body-sm outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--accent-red)]"
                  placeholder={
                    ruleType === 'ip'
                      ? 'e.g. 192.168.1.105'
                      : ruleType === 'app'
                      ? 'e.g. YouTube, TikTok, Netflix'
                      : 'e.g. facebook.com, netflix'
                  }
                  required
                />
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex items-center justify-center gap-1.5 py-2 rounded-md text-body-sm font-semibold transition-colors cursor-pointer text-white bg-[var(--accent-red)] hover:bg-red-700 disabled:opacity-50"
              >
                <Plus className="w-4 h-4" />
                <span>{isLoading ? 'Applying Filter...' : 'Apply Block Filter'}</span>
              </button>
            </form>

            {/* Notification messages */}
            {actionMessage && (
              <div
                className={`p-2.5 rounded-lg border text-caption flex items-start gap-2 animate-fade-in ${
                  actionMessage.type === 'success'
                    ? 'border-green-500/30 bg-green-500/10 text-[var(--accent-green)]'
                    : 'border-red-500/30 bg-red-500/10 text-[var(--accent-red)]'
                }`}
              >
                {actionMessage.type === 'success' ? (
                  <CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                ) : (
                  <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                )}
                <span>{actionMessage.text}</span>
              </div>
            )}

            {apiError && (
              <div className="p-2.5 rounded-lg border border-red-500/30 bg-red-500/10 text-[var(--accent-red)] text-caption flex items-start gap-2">
                <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>Backend Error: {apiError}</span>
              </div>
            )}
          </div>

          {/* Quick Info Box */}
          <div className="dpi-panel text-caption space-y-2 text-[var(--text-secondary)]">
            <div className="font-semibold text-[var(--text)] flex items-center gap-1.5">
              <AlertCircle className="w-3.5 h-3.5 text-[var(--accent-amber)]" />
              <span>Blocking behavior</span>
            </div>
            <p>
              When a rule matches, the engine immediately drops all subsequent packets in that traffic flow (bi-directionally).
            </p>
            <p>
              <strong>Domain filters</strong> match host substrings in HTTP Headers and TLS Client Hello Server Name Indication (SNI).
            </p>
          </div>
        </div>

        {/* Rules List Panel */}
        <div className="lg:col-span-2 space-y-4">
          <div className="dpi-card space-y-4">
            <div className="flex items-center justify-between gap-4">
              <div className="text-body-sm font-semibold text-[var(--text)]">Active Rules ({filteredRulesList.length})</div>
              
              {/* Search filter */}
              <div className="relative w-48 sm:w-64">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[var(--text-muted)]" />
                <input
                  type="text"
                  value={filterText}
                  onChange={(e) => setFilterText(e.target.value)}
                  placeholder="Filter rules..."
                  className="w-full pl-8 pr-3 py-1 rounded-md text-caption outline-none transition-colors border border-[var(--border)] bg-[var(--panel-soft)] text-[var(--text)] focus:border-[var(--border-strong)]"
                />
              </div>
            </div>

            <div className="overflow-x-auto">
              {filteredRulesList.length === 0 ? (
                <div className="py-12 text-center text-caption text-[var(--text-muted)] font-mono">
                  No blocking rules match current search filter.
                </div>
              ) : (
                <table className="dpi-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Match Criteria</th>
                      <th className="text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredRulesList.map((rule, idx) => (
                      <tr key={idx}>
                        <td>
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wide ${
                              rule.type === 'ip'
                                ? 'bg-[var(--accent-blue-soft)] text-[var(--accent-blue)]'
                                : rule.type === 'app'
                                ? 'bg-[var(--accent-violet-soft)] text-[var(--accent-violet)]'
                                : 'bg-[var(--accent-cyan-soft)] text-[var(--accent-cyan)]'
                            }`}
                          >
                            {rule.type === 'ip' ? 'IP' : rule.type === 'app' ? 'APP' : 'Domain'}
                          </span>
                        </td>
                        <td className="font-mono text-body-sm font-semibold text-[var(--text)]">{rule.value}</td>
                        <td className="text-right">
                          <button
                            onClick={() => handleDeleteRule(rule.type, rule.value)}
                            disabled={isLoading}
                            className="p-1 rounded hover:bg-[var(--panel-soft)] text-[var(--text-muted)] hover:text-[var(--accent-red)] transition-colors cursor-pointer"
                            title="Remove Block rule"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
