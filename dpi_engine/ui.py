from __future__ import annotations

import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple, Any

from dpi_engine.common import load_scapy, AppType, app_type_to_string, Rules
from dpi_engine.pipeline import DPIEngine


DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DPI Engine Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Geist:wght@300;400;500;600;700;800;900&family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap');
    :root {
      color-scheme: dark;
      --bg: #090909;
      --panel: #141414;
      --panel-soft: #1c1c1c;
      --panel-hover: #262626;
      --text: #ffffff;
      --muted: #999999;
      --text-muted: #666666;
      --line: #262626;
      --line-light: #3a3a3a;
      --line-soft: #1a1a1a;
      --blue: #0099ff;
      --blue-glow: rgba(0, 153, 255, 0.12);
      --green: #22c55e;
      --red: #ff3344;
      --amber: #ffaa00;
      --violet: #6a4cf5;
      --magenta: #d44df0;
      
      --radius-xs: 4px;
      --radius-sm: 6px;
      --radius-md: 10px;
      --radius-lg: 15px;
      --radius-xl: 20px;
      --radius-xxl: 30px;
      --radius-pill: 100px;
      --radius-full: 9999px;
      
      --shadow-2: 0px 1px 1px rgba(0,0,0,0.3), 0px 2px 2px rgba(0,0,0,0.2), inset 0 0 0 1px rgba(255,255,255,0.06);
      --shadow-4: 0px 2px 2px rgba(0,0,0,0.2), 0px 8px 16px -4px rgba(0,0,0,0.3), inset 0 0 0 1px rgba(255,255,255,0.06);
    }
    @media (prefers-color-scheme: light) {
      :root {
        color-scheme: light;
        --bg: #fafafa;
        --panel: #ffffff;
        --panel-soft: #f1f1f4;
        --panel-hover: #e8e8ed;
        --text: #0b0f19;
        --muted: #555566;
        --text-muted: #888899;
        --line: #e2e2e7;
        --line-light: #c7c7cc;
        --line-soft: #f0f0f5;
        --blue-glow: rgba(0, 153, 255, 0.08);
        --green: #16a34a;
        --red: #dc2626;
        --amber: #d97706;
        --violet: #5856d6;
        --magenta: #db2777;
        --shadow-2: 0px 2px 4px rgba(0,0,0,0.03), 0px 1px 1px rgba(0,0,0,0.02);
        --shadow-4: 0px 8px 16px rgba(0,0,0,0.06), 0px 4px 8px rgba(0,0,0,0.04);
      }
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: 'Inter', system-ui, -apple-system, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.30;
      font-size: 15px;
      letter-spacing: -0.15px;
      font-feature-settings: "cv01" 1, "cv05" 1, "cv09" 1, "cv11" 1, "ss03" 1, "ss07" 1, "dlig" 1;
      -webkit-font-smoothing: antialiased;
    }
    header {
      padding: 10px 24px;
      background: var(--bg);
      border-bottom: 1px solid var(--line-soft);
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      flex-wrap: wrap;
      height: 56px;
    }
    .logo-container {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .logo-icon {
      width: 32px;
      height: 32px;
      border-radius: var(--radius-full);
      display: flex;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--line);
      background: var(--panel-soft);
      box-shadow: inset 0 0 0 1px rgba(255,255,255,0.06);
    }
    .logo-icon svg {
      width: 14px;
      height: 14px;
      color: var(--blue);
    }
    header h1 {
      margin: 0;
      font-family: 'Geist', sans-serif;
      font-size: 16px;
      font-weight: 700;
      letter-spacing: -0.6px;
      color: var(--text);
    }
    header h1 span {
      color: var(--blue);
    }
    .sub {
      margin-top: 2px;
      color: var(--muted);
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
    }
    .status {
      border: 1px solid var(--line);
      border-radius: var(--radius-pill);
      padding: 5px 12px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: .05em;
      background: var(--panel-soft);
      color: var(--text);
      display: inline-flex;
      align-items: center;
      gap: 6px;
      box-shadow: var(--shadow-2);
    }
    .status::before {
      content: '';
      display: inline-block;
      width: 7px;
      height: 7px;
      background: var(--blue);
      border-radius: 50%;
    }
    .status.running::before {
      background: var(--green);
      animation: pulse-green 1.5s infinite;
    }
    .status.idle::before {
      background: var(--blue);
      animation: pulse-blue 1.5s infinite;
    }
    .status.failed::before {
      background: var(--red);
      animation: pulse-red 1.5s infinite;
    }
    
    @keyframes pulse-green {
      0% { transform: scale(0.9); opacity: 0.6; }
      50% { transform: scale(1.2); opacity: 1; }
      100% { transform: scale(0.9); opacity: 0.6; }
    }
    @keyframes pulse-blue {
      0% { transform: scale(0.9); opacity: 0.6; }
      50% { transform: scale(1.2); opacity: 1; }
      100% { transform: scale(0.9); opacity: 0.6; }
    }
    @keyframes pulse-red {
      0% { transform: scale(0.9); opacity: 0.6; }
      50% { transform: scale(1.2); opacity: 1; }
      100% { transform: scale(0.9); opacity: 0.6; }
    }
    
    main {
      width: min(1400px, 100%);
      margin: 0 auto;
      padding: 24px;
    }
    .grid {
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 20px;
    }
    .card {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: var(--radius-xl);
      padding: 20px;
      box-shadow: var(--shadow-2);
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .card:hover {
      border-color: var(--line-light);
      box-shadow: var(--shadow-4);
    }
    .metric { grid-column: span 1; min-width: 0; }
    .metric .label {
      color: var(--muted);
      font-size: 11px;
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: .06em;
      font-family: 'JetBrains Mono', monospace;
    }
    .metric .value {
      margin-top: 8px;
      font-size: 26px;
      line-height: 1.1;
      font-weight: 700;
      letter-spacing: -0.8px;
      color: var(--text);
      font-family: 'Geist', sans-serif;
    }
    .wide { grid-column: span 3; }
    .full { grid-column: 1 / -1; }
    h2 {
      margin: 0 0 16px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: -0.14px;
      text-transform: uppercase;
      color: var(--muted);
      font-family: 'JetBrains Mono', monospace;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }
    th, td {
      padding: 10px 14px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: middle;
      white-space: nowrap;
    }
    th {
      color: var(--muted);
      font-weight: 600;
      background: var(--panel-soft);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      font-family: 'JetBrains Mono', monospace;
      border-bottom: 1px solid var(--line);
    }
    tr:hover td {
      background: var(--panel-soft);
    }
    td.domain, td.path { white-space: normal; word-break: break-word; }
    .bar-row {
      display: grid;
      grid-template-columns: 120px 1fr 100px;
      gap: 12px;
      align-items: center;
      margin: 12px 0;
      font-size: 13px;
    }
    .track {
      height: 8px;
      background: var(--panel-soft);
      border-radius: var(--radius-pill);
      overflow: hidden;
    }
    .fill {
      height: 100%;
      background: linear-gradient(90deg, var(--violet), var(--blue));
      border-radius: var(--radius-pill);
      min-width: 2px;
    }
    .pill {
      border-radius: var(--radius-pill);
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 600;
      display: inline-block;
      font-family: 'JetBrains Mono', monospace;
    }
    .forward { color: var(--green); background: var(--accent-green-soft); border: 1px solid rgba(34, 197, 94, 0.15); }
    .drop { color: var(--red); background: var(--accent-red-soft); border: 1px solid rgba(255, 51, 68, 0.15); }
    .eti-benign { color: var(--green); background: var(--accent-green-soft); border: 1px solid rgba(34, 197, 94, 0.15); }
    .eti-suspicious { color: var(--amber); background: var(--accent-amber-soft); border: 1px solid rgba(255, 170, 0, 0.15); }
    .eti-malicious { color: var(--red); background: var(--accent-red-soft); border: 1px solid rgba(255, 51, 68, 0.2); }
    .muted { color: var(--text-muted); }
    .thread-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
      gap: 12px;
    }
    .thread {
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      padding: 12px;
      background: var(--panel-soft);
      transition: border-color 0.2s;
    }
    .thread:hover {
      border-color: var(--line-light);
    }
    .thread b { display: block; font-size: 13px; color: var(--text); }
    .thread span { color: var(--muted); font-size: 11px; font-family: 'JetBrains Mono', monospace; }
    .controls {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
      align-items: end;
    }
    label {
      display: block;
      color: var(--muted);
      font-size: 11px;
      margin-bottom: 6px;
      font-weight: 500;
      font-family: 'JetBrains Mono', monospace;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    input, select {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: var(--radius-md);
      padding: 8px 12px;
      background: var(--panel-soft);
      color: var(--text);
      font-family: inherit;
      font-size: 14px;
      min-height: 40px;
      outline: none;
      transition: border-color 0.2s, background-color 0.2s;
    }
    input:focus, select:focus {
      border-color: var(--blue);
      background: var(--panel);
      box-shadow: 0 0 0 1px var(--blue-glow);
    }
    button {
      width: 100%;
      min-height: 40px;
      cursor: pointer;
      font-family: 'Inter', sans-serif;
      font-size: 14px;
      font-weight: 500;
      letter-spacing: -0.14px;
      border-radius: var(--radius-pill);
      padding: 10px 18px;
      border: 1px solid var(--line);
      background: var(--panel-soft);
      color: var(--text);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      transition: transform 100ms ease, background-color 150ms ease, border-color 150ms ease;
    }
    button:hover {
      background-color: var(--panel-hover);
      border-color: var(--line-light);
    }
    button:active {
      transform: scale(0.96);
    }
    button.primary {
      background: var(--text);
      border: none;
      color: var(--text-inverse);
    }
    button.primary:hover {
      opacity: 0.95;
      background: var(--text);
    }
    button.danger {
      background: var(--red);
      border-color: var(--red);
      color: #fff;
    }
    button.danger:hover {
      background: #e62233;
      border-color: #e62233;
    }
    .msg {
      margin-top: 10px;
      min-height: 18px;
      color: var(--muted);
      font-size: 13px;
      font-family: 'JetBrains Mono', monospace;
    }
    .rule-list {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 10px;
    }
    .rule-chip {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid var(--line);
      border-radius: var(--radius-pill);
      background: var(--panel-soft);
      padding: 4px 12px;
      font-size: 12px;
      box-shadow: var(--shadow-2);
    }
    .rule-chip button {
      width: auto;
      min-height: 0;
      padding: 0;
      border: 0;
      background: transparent;
      color: var(--red);
      font-size: 18px;
      line-height: 1;
      margin-left: 4px;
      display: flex;
      align-items: center;
    }
    .rule-chip button:hover {
      background: transparent;
    }
    .font-mono {
      font-family: 'JetBrains Mono', monospace;
    }
    .chart-container {
      position: relative;
      height: 220px;
      width: 100%;
    }
    .anomaly-list {
      max-height: 250px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
    }
    .anomaly-item {
      display: flex;
      gap: 12px;
      align-items: flex-start;
      padding: 12px;
      border-bottom: 1px solid var(--line);
    }
    .anomaly-item:last-child {
      border-bottom: none;
    }
    .anomaly-badge {
      background: var(--red);
      color: #fff;
      font-size: 10px;
      font-weight: 700;
      padding: 2px 6px;
      border-radius: var(--radius-xs);
      letter-spacing: 0.05em;
      text-transform: uppercase;
      white-space: nowrap;
    }
    .pulsing {
      box-shadow: 0 0 0 0 rgba(255, 51, 68, 0.6);
      animation: pulse-red-alert 1.5s infinite cubic-bezier(0.66, 0, 0, 1);
    }
    @keyframes pulse-red-alert {
      to { box-shadow: 0 0 0 8px rgba(255, 51, 68, 0); }
    }
    .anomaly-details b {
      color: var(--red);
      font-size: 13px;
    }
    .anomaly-details p {
      margin: 4px 0;
      font-size: 13px;
    }
    .anomaly-time {
      font-size: 11px;
      color: var(--muted);
      display: block;
      margin-top: 2px;
      font-family: 'JetBrains Mono', monospace;
    }
    @media (max-width: 1150px) {
      .metric { grid-column: span 2; }
      .wide { grid-column: 1 / -1; }
    }
    @media (max-width: 680px) {
      main { padding: 16px; }
      .grid { grid-template-columns: repeat(2, 1fr); gap: 12px; }
      .metric { grid-column: span 1; }
      .full, .wide { grid-column: 1 / -1; }
      .metric .value { font-size: 22px; }
      table { font-size: 12px; }
      th, td { padding: 8px 6px; }
    }
    #infoBtn {
      background: none;
      border: 1px solid var(--line);
      border-radius: 50%;
      width: 28px;
      height: 28px;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      color: var(--muted);
      font-family: 'Georgia', serif;
      font-size: 16px;
      font-weight: bold;
      padding: 0;
      transition: all 0.2s ease;
    }
    #infoBtn:hover {
      color: var(--blue);
      border-color: var(--blue);
      background: rgba(0, 153, 255, 0.1);
      box-shadow: 0 0 8px var(--blue-glow);
    }
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(4, 6, 12, 0.85);
      backdrop-filter: blur(12px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s ease;
    }
    .modal-overlay.active {
      opacity: 1;
      pointer-events: auto;
    }
    .modal-box {
      background: var(--panel);
      border: 1px solid var(--line-light);
      border-radius: var(--radius-xl);
      width: 90%;
      max-width: 650px;
      max-height: 85vh;
      overflow-y: auto;
      box-shadow: var(--shadow-4), 0 0 20px var(--blue-glow);
      transform: scale(0.95);
      transition: transform 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
    }
    .modal-overlay.active .modal-box {
      transform: scale(1);
    }
    .modal-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--line);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .modal-header h3 {
      margin: 0;
      font-size: 18px;
      font-weight: 700;
      color: var(--blue);
      font-family: 'Geist', sans-serif;
      letter-spacing: -0.4px;
    }
    .modal-close {
      background: none;
      border: none;
      font-size: 24px;
      color: var(--muted);
      cursor: pointer;
      line-height: 1;
      padding: 0;
    }
    .modal-close:hover {
      color: var(--red);
    }
    .modal-body {
      padding: 20px;
      font-size: 14px;
      line-height: 1.6;
    }
    .modal-body h4 {
      color: var(--text);
      margin-top: 20px;
      margin-bottom: 8px;
      font-size: 15px;
      border-left: 3px solid var(--blue);
      padding-left: 8px;
      font-family: 'Geist', sans-serif;
    }
    .modal-body h4:first-of-type {
      margin-top: 0;
    }
    .modal-body p {
      margin: 0 0 12px 0;
      color: var(--muted);
    }
    .modal-body ul, .modal-body ol {
      margin: 0 0 16px 0;
      padding-left: 20px;
      color: var(--muted);
    }
    .modal-body li {
      margin-bottom: 6px;
    }
    .badge-info {
      background: var(--accent-blue-soft);
      color: var(--blue);
      padding: 2px 6px;
      border-radius: var(--radius-xs);
      font-family: monospace;
      font-size: 12px;
    }
    .badge-warn {
      background: var(--accent-amber-soft);
      color: var(--amber);
      padding: 2px 6px;
      border-radius: var(--radius-xs);
      font-family: monospace;
      font-size: 12px;
    }
    .badge-danger {
      background: var(--accent-red-soft);
      color: var(--red);
      padding: 2px 6px;
      border-radius: var(--radius-xs);
      font-family: monospace;
      font-size: 12px;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo-container">
      <div class="logo-icon">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 9.7a1 1 0 0 1-.68 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 .76-.97l8-2a1 1 0 0 1 .48 0l8 2A1 1 0 0 1 20 6z"/></svg>
      </div>
      <div>
        <h1>DPI Engine<span>.</span></h1>
        <div class="sub" id="files">Waiting for data...</div>
      </div>
    </div>
    <div style="display: flex; align-items: center; gap: 12px;">
      <div class="status idle" id="status">Idle</div>
      <button id="infoBtn" onclick="openInfoModal()" title="Help Center">i</button>
    </div>
  </header>
  <main>
    <section class="grid">
      <div class="card metric"><div class="label">Total Packets</div><div class="value" id="total">0</div></div>
      <div class="card metric"><div class="label">Forwarded</div><div class="value" id="forwarded">0</div></div>
      <div class="card metric"><div class="label">Dropped</div><div class="value" id="dropped">0</div></div>
      <div class="card metric"><div class="label">Drop Rate</div><div class="value" id="dropRate">0%</div></div>
      <div class="card metric"><div class="label">TCP Packets</div><div class="value" id="tcp">0</div></div>
      <div class="card metric"><div class="label">UDP Packets</div><div class="value" id="udp">0</div></div>

      <div class="card full">
        <h2>Live Capture Controls</h2>
        <div class="controls">
          <div>
            <label for="iface">Interface</label>
            <select id="iface"><option value="">Scapy default</option></select>
          </div>
          <div>
            <label for="liveOutput">Output PCAP</label>
            <input id="liveOutput" value="live_output.pcap">
          </div>
          <div>
            <label for="duration">Duration seconds</label>
            <input id="duration" type="number" min="1" placeholder="empty = manual stop">
          </div>
          <div>
            <label for="count">Packet count</label>
            <input id="count" type="number" min="0" placeholder="0 = unlimited">
          </div>
          <div>
            <label for="bpf">BPF filter</label>
            <input id="bpf" placeholder="tcp or udp">
          </div>
          <div>
            <button class="primary" id="startBtn" onclick="startLive()">Start Live</button>
          </div>
          <div>
            <button onclick="loadInterfaces()">Refresh Interfaces</button>
          </div>
          <div>
            <button class="danger" id="stopBtn" onclick="stopLive()">Stop Live</button>
          </div>
        </div>
        <div class="msg" id="controlMsg"></div>
      </div>

      <div class="card full">
        <h2>Blocking Rules</h2>
        <div class="controls">
          <div>
            <label for="ruleType">Type</label>
            <select id="ruleType">
              <option value="app">App</option>
              <option value="domain">Domain</option>
              <option value="ip">Source IP</option>
            </select>
          </div>
          <div>
            <label for="ruleValue">Value</label>
            <input id="ruleValue" placeholder="YouTube / facebook.com / 192.168.1.50">
          </div>
          <div>
            <button class="primary" onclick="addRule()">Add Rule</button>
          </div>
        </div>
        <div class="msg" id="ruleMsg"></div>
        <div id="rules"></div>
      </div>

      <!-- Phase 3 Flow Analytics Charts -->
      <div class="card wide">
        <h2>Rolling Throughput & PPS</h2>
        <div class="chart-container">
          <canvas id="throughputChart"></canvas>
        </div>
      </div>

      <div class="card wide">
        <h2>Protocol Distribution (Bytes)</h2>
        <div class="chart-container">
          <canvas id="protocolChart"></canvas>
        </div>
      </div>

      <div class="card wide">
        <h2>Recent Protocol Anomalies</h2>
        <div class="anomaly-list" id="anomaliesList">
          <div style="padding:16px; text-align:center" class="muted">No anomalies detected yet.</div>
        </div>
      </div>

      <div class="card wide">
        <h2>Application Breakdown</h2>
        <div id="apps" class="muted">No application data yet.</div>
      </div>

      <div class="card wide">
        <h2>Thread Load</h2>
        <div class="thread-grid" id="threads"></div>
      </div>

      <div class="card wide">
        <h2>Detected Domains</h2>
        <div style="max-height: 250px; overflow-y: auto;">
          <table>
            <thead><tr><th>Domain</th><th>App</th></tr></thead>
            <tbody id="domains"><tr><td class="muted" colspan="2">No domains detected yet.</td></tr></tbody>
          </table>
        </div>
      </div>

      <div class="card wide">
        <h2>Run Details</h2>
        <table>
          <tbody>
            <tr><th>Input</th><td class="path" id="inputFile">-</td></tr>
            <tr><th>Output</th><td class="path" id="outputFile">-</td></tr>
            <tr><th>Bytes</th><td id="bytes">0</td></tr>
            <tr><th>Elapsed</th><td id="elapsed">0.0s</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Phase 3 Flow Analytics Top Talkers -->
      <div class="card full">
        <h2>Top Talkers (Flow Analytics)</h2>
        <div style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th>5-Tuple</th>
                <th>Proto</th>
                <th>App</th>
                <th>Domain/SNI</th>
                <th>Packets</th>
                <th>Bytes</th>
                <th>Duration</th>
                <th>Throughput</th>
              </tr>
            </thead>
            <tbody id="topTalkers">
              <tr><td class="muted" colspan="8">No flow analytics data yet.</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div class="card full">
        <h2>Recent Packet Decisions</h2>
        <div style="overflow-x: auto;">
          <table>
            <thead>
              <tr>
                <th>ID</th><th>Action</th><th>Source</th><th>Destination</th><th>Country</th>
                <th>Proto</th><th>App</th><th>Domain</th><th>Size</th><th>FP</th>
                <th>JA3</th><th>JA4</th><th>ETI Threat</th>
              </tr>
            </thead>
            <tbody id="packets"><tr><td class="muted" colspan="13">No packet decisions yet.</td></tr></tbody>
          </table>
        </div>
      </div>
    </section>
  </main>

  <script>
    const fmt = new Intl.NumberFormat();
    
    // Chart.js state variables
    let throughputChart = null;
    let protocolChart = null;
    let throughputHistory = []; // {time, bps, pps}

    function initCharts() {
      const tCtx = document.getElementById("throughputChart").getContext("2d");
      throughputChart = new Chart(tCtx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [
            {
              label: 'Throughput (Mbps)',
              data: [],
              borderColor: '#3b82f6',
              backgroundColor: 'rgba(59, 130, 246, 0.1)',
              yAxisID: 'y-bps',
              borderWidth: 2,
              tension: 0.3,
              fill: true
            },
            {
              label: 'Packet Rate (pps)',
              data: [],
              borderColor: '#10b981',
              backgroundColor: 'transparent',
              yAxisID: 'y-pps',
              borderWidth: 2,
              tension: 0.3
            }
          ]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            'y-bps': {
              type: 'linear',
              position: 'left',
              title: { display: true, text: 'Mbps', color: '#94a3b8' },
              grid: { color: 'rgba(75, 85, 99, 0.2)' },
              ticks: { color: '#94a3b8' }
            },
            'y-pps': {
              type: 'linear',
              position: 'right',
              title: { display: true, text: 'packets/sec', color: '#94a3b8' },
              grid: { drawOnChartArea: false },
              ticks: { color: '#94a3b8' }
            },
            x: {
              grid: { color: 'rgba(75, 85, 99, 0.2)' },
              ticks: { color: '#94a3b8' }
            }
          },
          plugins: {
            legend: { labels: { color: '#f8fafc' } }
          }
        }
      });

      const pCtx = document.getElementById("protocolChart").getContext("2d");
      protocolChart = new Chart(pCtx, {
        type: 'doughnut',
        data: {
          labels: ['HTTP', 'HTTPS', 'HTTP/2', 'QUIC', 'DNS', 'Unknown'],
          datasets: [{
            data: [0, 0, 0, 0, 0, 0],
            backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#6b7280'],
            borderWidth: 1,
            borderColor: '#111827'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: { 
              position: 'right',
              labels: { color: '#f8fafc' }
            }
          }
        }
      });
    }

    function setText(id, value) {
      const el = document.getElementById(id);
      if (el) el.textContent = value;
    }
    
    function escapeHtml(value) {
      return String(value ?? "").replace(/[&<>"']/g, ch => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
      }[ch]));
    }
    
    function renderApps(apps) {
      const el = document.getElementById("apps");
      if (!apps.length) {
        el.innerHTML = '<span class="muted">No application data yet.</span>';
        return;
      }
      el.innerHTML = apps.map(app => `
        <div class="bar-row">
          <div>${escapeHtml(app.name)}</div>
          <div class="track"><div class="fill" style="width:${Math.max(1, app.pct)}%"></div></div>
          <div>${fmt.format(app.count)} (${app.pct.toFixed(1)}%)</div>
        </div>
      `).join("");
    }
    
    function renderThreads(data) {
      const rows = [...data.lb_threads, ...data.fp_threads];
      document.getElementById("threads").innerHTML = rows.map(row => `
        <div class="thread"><b>${escapeHtml(row.name)}</b><span>${fmt.format(row.packets)} packets</span></div>
      `).join("");
    }
    
    function renderDomains(domains) {
      const tbody = document.getElementById("domains");
      if (!domains.length) {
        tbody.innerHTML = '<tr><td class="muted" colspan="2">No domains detected yet.</td></tr>';
        return;
      }
      tbody.innerHTML = domains.map(row => `
        <tr><td class="domain font-mono">${escapeHtml(row.domain)}</td><td>${escapeHtml(row.app)}</td></tr>
      `).join("");
    }
    
    function renderPackets(packets) {
      const tbody = document.getElementById("packets");
      if (!packets.length) {
        tbody.innerHTML = '<tr><td class="muted" colspan="13">No packet decisions yet.</td></tr>';
        return;
      }
      tbody.innerHTML = packets.slice(0, 100).map(pkt => {
        const cls = pkt.action === "DROP" ? "drop" : "forward";
        
        let etiCls = "muted";
        if (pkt.eti) {
          if (pkt.eti.includes("MALICIOUS")) etiCls = "eti-malicious";
          else if (pkt.eti.includes("SUSPICIOUS")) etiCls = "eti-suspicious";
          else if (pkt.eti.includes("BENIGN")) etiCls = "eti-benign";
        }
        
        return `
          <tr>
            <td class="font-mono">${pkt.id}</td>
            <td><span class="pill ${cls}">${escapeHtml(pkt.action)}</span></td>
            <td class="font-mono">${escapeHtml(pkt.src)}</td>
            <td class="font-mono">${escapeHtml(pkt.dst)}</td>
            <td><span class="pill font-mono" style="font-size:10px; color:#a1a1aa; background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); padding:2px 6px; border-radius:3px;">${escapeHtml(pkt.country || "Unknown")}</span></td>
            <td class="font-mono">${escapeHtml(pkt.protocol)}</td>
            <td>${escapeHtml(pkt.app)}</td>
            <td class="domain">${escapeHtml(pkt.domain || "-")}</td>
            <td class="font-mono">${fmt.format(pkt.size)}</td>
            <td>FP${pkt.fp}</td>
            <td class="font-mono" title="${escapeHtml(pkt.ja3)}">${escapeHtml(pkt.ja3 ? pkt.ja3.substring(0, 8) + "..." : "-")}</td>
            <td class="font-mono" title="${escapeHtml(pkt.ja4)}">${escapeHtml(pkt.ja4 ? pkt.ja4.substring(0, 8) + "..." : "-")}</td>
            <td><span class="pill ${etiCls}">${escapeHtml(pkt.eti || "BENIGN (100%)")}</span></td>
          </tr>
        `;
      }).join("");
    }
    
    function renderRules(rules) {
      const root = document.getElementById("rules");
      const groups = [
        ["app", "Blocked Apps", rules?.apps || []],
        ["domain", "Blocked Domains", rules?.domains || []],
        ["ip", "Blocked Source IPs", rules?.ips || []]
      ];
      root.innerHTML = groups.map(([type, title, values]) => `
        <div style="margin-top:12px">
          <b>${title}</b>
          <div class="rule-list">
            ${values.length ? values.map(value => `
              <span class="rule-chip">
                ${escapeHtml(value)}
                <button title="Remove" onclick="removeRule('${type}', '${escapeHtml(value).replace(/'/g, "\\'")}')">&times;</button>
              </span>
            `).join("") : '<span class="muted" style="font-size:12px">None</span>'}
          </div>
        </div>
      `).join("");
    }

    async function api(path, options = {}) {
      const res = await fetch(path, {
        cache: "no-store",
        headers: { "Content-Type": "application/json" },
        ...options
      });
      let data = {};
      try { data = await res.json(); } catch (_) {}
      if (!res.ok) {
        throw new Error(data.message || data.error || `Request failed: ${res.status}`);
      }
      return data;
    }

    async function loadInterfaces() {
      const msg = document.getElementById("controlMsg");
      try {
        const data = await api("/api/interfaces");
        const select = document.getElementById("iface");
        select.innerHTML = '<option value="">Scapy default</option>' + data.interfaces.map(iface => `
          <option value="${escapeHtml(iface.name)}">${escapeHtml(iface.name)}</option>
        `).join("");
        msg.textContent = data.ok ? "Interfaces loaded." : data.error;
      } catch (err) {
        msg.textContent = err.message;
      }
    }

    async function startLive() {
      const msg = document.getElementById("controlMsg");
      try {
        const payload = {
          iface: document.getElementById("iface").value,
          output_file: document.getElementById("liveOutput").value,
          duration: document.getElementById("duration").value,
          count: document.getElementById("count").value || 0,
          bpf: document.getElementById("bpf").value
        };
        const data = await api("/api/live/start", {
          method: "POST",
          body: JSON.stringify(payload)
        });
        msg.textContent = data.message;
        refresh();
      } catch (err) {
        msg.textContent = err.message;
      }
    }

    async function stopLive() {
      const msg = document.getElementById("controlMsg");
      try {
        const data = await api("/api/live/stop", { method: "POST", body: "{}" });
        msg.textContent = data.message;
        refresh();
      } catch (err) {
        msg.textContent = err.message;
      }
    }

    async function addRule() {
      const msg = document.getElementById("ruleMsg");
      try {
        const payload = {
          type: document.getElementById("ruleType").value,
          value: document.getElementById("ruleValue").value
        };
        const data = await api("/api/rules", {
          method: "POST",
          body: JSON.stringify(payload)
        });
        msg.textContent = data.message;
        document.getElementById("ruleValue").value = "";
        renderRules(data.rules);
        refresh();
      } catch (err) {
        msg.textContent = err.message;
      }
    }

    async function removeRule(type, value) {
      const msg = document.getElementById("ruleMsg");
      try {
        const data = await api("/api/rules", {
          method: "DELETE",
          body: JSON.stringify({ type, value })
        });
        msg.textContent = data.message;
        renderRules(data.rules);
        refresh();
      } catch (err) {
        msg.textContent = err.message;
      }
    }

    async function refresh() {
      const res = await fetch("/api/stats", { cache: "no-store" });
      const data = await res.json();
      
      setText("status", data.status);
      setText("files", `${data.input_file || "-"} -> ${data.output_file || "-"}`);
      setText("total", fmt.format(data.total_packets));
      setText("forwarded", fmt.format(data.forwarded));
      setText("dropped", fmt.format(data.dropped));
      setText("dropRate", `${data.drop_rate.toFixed(1)}%`);
      setText("tcp", fmt.format(data.tcp_packets));
      setText("udp", fmt.format(data.udp_packets));
      setText("inputFile", data.input_file || "-");
      setText("outputFile", data.output_file || "-");
      setText("bytes", fmt.format(data.total_bytes));
      setText("elapsed", `${data.elapsed.toFixed(1)}s`);
      
      renderApps(data.apps);
      renderThreads(data);
      renderDomains(data.domains);
      renderPackets(data.recent_packets);
      renderRules(data.rules || { ips: [], apps: [], domains: [] });

      document.getElementById("startBtn").disabled = !!data.capture_running;
      document.getElementById("stopBtn").disabled = !data.capture_running;
      if (data.last_error) {
        document.getElementById("controlMsg").textContent = data.last_error;
      }

      // Update Flow Analytics Charts (Phase 3)
      const roll = data.analytics?.rolling_bps !== undefined ? data.analytics : { rolling_bps: 0, rolling_pps: 0 };
      const nowStr = new Date().toLocaleTimeString();
      throughputHistory.push({
        time: nowStr,
        bps: (roll.rolling_bps / 1000000.0), // convert to Mbps
        pps: roll.rolling_pps
      });
      if (throughputHistory.length > 20) {
        throughputHistory.shift();
      }
      
      if (throughputChart) {
        throughputChart.data.labels = throughputHistory.map(h => h.time);
        throughputChart.data.datasets[0].data = throughputHistory.map(h => h.bps);
        throughputChart.data.datasets[1].data = throughputHistory.map(h => h.pps);
        throughputChart.update('none');
      }

      const pDist = data.analytics?.protocol_distribution || {};
      const order = ['HTTP', 'HTTPS', 'HTTP/2', 'QUIC', 'DNS', 'Unknown'];
      const pData = order.map(proto => (pDist[proto]?.bytes || 0) / 1024.0); // KB
      if (protocolChart) {
        protocolChart.data.datasets[0].data = pData;
        protocolChart.update('none');
      }

      // Render Top Talkers table
      const talkers = data.analytics?.top_talkers || [];
      const tbodyTalkers = document.getElementById("topTalkers");
      if (!talkers.length) {
        tbodyTalkers.innerHTML = '<tr><td class="muted" colspan="8" style="text-align:center">No flow analytics data yet.</td></tr>';
      } else {
        tbodyTalkers.innerHTML = talkers.map(t => {
          let bpsStr = "";
          if (t.throughput > 1000000.0) bpsStr = (t.throughput / 1000000.0).toFixed(2) + " MB/s";
          else if (t.throughput > 1000.0) bpsStr = (t.throughput / 1000.0).toFixed(2) + " KB/s";
          else bpsStr = t.throughput.toFixed(0) + " B/s";
          
          let bytesStr = "";
          if (t.bytes > 1000000.0) bytesStr = (t.bytes / 1000000.0).toFixed(2) + " MB";
          else if (t.bytes > 1000.0) bytesStr = (t.bytes / 1000.0).toFixed(2) + " KB";
          else bytesStr = t.bytes + " B";
          
          return `
            <tr>
              <td class="domain font-mono" style="font-size:12px">${escapeHtml(t.tuple)}</td>
              <td><span class="pill font-mono bg-slate-700">${escapeHtml(t.proto_name)}</span></td>
              <td>${escapeHtml(t.app)}</td>
              <td class="domain">${escapeHtml(t.sni || "-")}</td>
              <td class="font-mono">${fmt.format(t.packets)}</td>
              <td class="font-mono">${bytesStr}</td>
              <td class="font-mono">${t.duration.toFixed(2)}s</td>
              <td class="font-mono"><b>${bpsStr}</b></td>
            </tr>
          `;
        }).join("");
      }

      // Render Recent Protocol Anomalies (Phase 4)
      const anomalies = data.recent_anomalies || [];
      const elAnomList = document.getElementById("anomaliesList");
      if (!anomalies.length) {
        elAnomList.innerHTML = '<div style="padding:16px; text-align:center" class="muted">No anomalies detected yet.</div>';
      } else {
        elAnomList.innerHTML = anomalies.map(anom => {
          const dateStr = new Date(anom.timestamp * 1000).toLocaleTimeString();
          const mitreBadge = anom.mitre_id ? `
            <span style="font-family: monospace; font-size: 10px; color: #f87171; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); padding: 1px 4px; border-radius: 3px; margin-left: 6px;">
              MITRE ${escapeHtml(anom.mitre_id)} (${escapeHtml(anom.mitre_technique)})
            </span>
          ` : "";
          return `
            <div class="anomaly-item">
              <span class="anomaly-badge pulsing">Alert</span>
              <div class="anomaly-details">
                <b>${escapeHtml(anom.type)}</b>${mitreBadge} - <span class="muted font-mono" style="font-size:12px">${escapeHtml(anom.flow)}</span>
                <p class="anomaly-desc">${escapeHtml(anom.description)}</p>
                <span class="anomaly-time">${dateStr} [App: ${escapeHtml(anom.app)}]</span>
              </div>
            </div>
          `;
        }).join("");
      }
    }

    initCharts();
    loadInterfaces();
    refresh();
    setInterval(refresh, 1000);

    window.openInfoModal = function() {
      document.getElementById("infoModal").classList.add("active");
    };
    window.closeInfoModal = function() {
      document.getElementById("infoModal").classList.remove("active");
    };
    window.addEventListener("click", function(event) {
      const modal = document.getElementById("infoModal");
      if (event.target === modal) {
        window.closeInfoModal();
      }
    });
  </script>

  <!-- Modal Overlay -->
  <div class="modal-overlay" id="infoModal">
    <div class="modal-box">
      <div class="modal-header">
        <h3>DPI Platform Help Center</h3>
        <button class="modal-close" onclick="closeInfoModal()">&times;</button>
      </div>
      <div class="modal-body">
        <h4>1. About the Application</h4>
        <p>
          This is a <b>Deep Packet Inspection (DPI) Engine</b> dashboard control panel. The platform captures and analyzes network traffic packets in real time from your local network interfaces. It incorporates advanced AI classifiers (Random Forest) and deep protocol anomaly detection engines.
        </p>

        <h4>2. Key Features</h4>
        <ul>
          <li><b>Real-time Sniffing & Capture:</b> Live capture and processing of incoming and outgoing network traffic.</li>
          <li><b>Active Traffic Blocking:</b> Injection of spoofed TCP RST packets (for TCP connections) and ICMP Port Unreachable packets (for UDP/QUIC connections) to actively disrupt blocked traffic.</li>
          <li><b>DNS IP Harvesting:</b> Dynamically parses DNS responses to extract resolved IP addresses for blocked domains, adding them to the firewall rules on the fly to bypass QUIC/HTTP3 encryption limitations.</li>
          <li><b>Flow Analytics:</b> Real-time bandwidth usage, throughput, top talkers, and protocol distribution tracking with dynamic charts.</li>
          <li><b>Anomaly Alerts:</b> Live warnings for network events like TCP SYN Floods, HTTP Smuggling, and DNS Tunneling.</li>
        </ul>

        <h4>3. How to Use the Features</h4>
        <ol>
          <li><b>Start/Stop Sniffing:</b> Select your preferred network interface (or keep <i>Scapy default</i>) at the top of the controls card, configure optional limits, and click <b>Start Live</b>. Click <b>Stop Live</b> to end the capture session.</li>
          <li><b>Configure Blocking Rules:</b> Under the Rules panel, select a type (App, Domain, or IP), enter the corresponding value (e.g., <code>github.com</code> or <code>192.168.1.50</code>), and click <b>Add Rule</b>. The engine applies the block list instantaneously.</li>
          <li><b>Monitor Security Alerts:</b> Scroll down to view anomalous network activities, ETI classifications, and throughput per flow.</li>
        </ol>

        <h4>4. Exceptions & Blocking Limitations (Important)</h4>
        <p>
          <b>Why Google and YouTube blocks might fail initially:</b>
        </p>
        <ul>
          <li><b>QUIC / HTTP3 (UDP 443) bypass:</b> Google and YouTube use the UDP-based QUIC protocol by default. Its TLS handshake payload is encrypted within QUIC Initial packets, preventing standard SNI extraction.</li>
          <li><b>Local Loopback Restriction:</b> If the browser and DPI engine run on the same Windows machine, the local OS network stack drops spoofed raw ICMP packets destined for its own MAC, bypassing the client-side block.</li>
          <li><b>DNS over HTTPS (DoH):</b> Browsers using encrypted DoH bypass standard DNS harvesting.</li>
        </ul>
        <p>
          <b>How to resolve this (Workaround):</b><br>
          To force browsers to fall back to standard TCP (HTTP/2) where they can be successfully blocked, run this command in an <b>Administrator PowerShell</b> terminal to block outbound UDP port 443:
          <code style="display:block; padding:8px; background:var(--panel-soft); border-radius:4px; margin-top:4px; font-size:11px; font-family: monospace;">New-NetFirewallRule -DisplayName "Block QUIC" -Direction Outbound -Protocol UDP -RemotePort 443 -Action Block</code>
        </p>
        <p>
          <b>Which apps/domains can be blocked directly?</b>
        </p>
        <ul>
          <li><span class="badge-danger">GitHub.com</span> - Runs entirely over TCP, blocked instantly.</li>
          <li><span class="badge-danger">Standard Web Services</span> - Facebook, Netflix, Amazon, and standard HTTP/HTTPS websites.</li>
          <li><span class="badge-warn">DNS Queries</span> - Port 53 UDP requests.</li>
          <li><span class="badge-info">Local LAN IPs</span> - Any local or remote IP address.</li>
        </ul>
      </div>
    </div>
  </div>
</body>
</html>
"""


class DashboardController:
    def __init__(self, config: DPIEngine.Config) -> None:
        self.config = config
        self.lock = threading.Lock()
        self.rule_ips: set[str] = set()
        self.rule_apps: set[str] = set()
        self.rule_domains: set[str] = set()
        self.active_engine: Optional[DPIEngine] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.stop_event: Optional[threading.Event] = None
        self.last_error = ""

    def dashboard_payload(self) -> Dict[str, object]:
        with self.lock:
            engine = self.active_engine
            running = self.capture_thread is not None and self.capture_thread.is_alive()
            last_error = self.last_error

        if engine is not None:
            payload = engine.dashboard_payload()
        else:
            payload = {
                "status": "idle",
                "input_file": "",
                "output_file": "",
                "elapsed": 0.0,
                "total_packets": 0,
                "total_bytes": 0,
                "forwarded": 0,
                "dropped": 0,
                "drop_rate": 0.0,
                "tcp_packets": 0,
                "udp_packets": 0,
                "apps": [],
                "domains": [],
                "lb_threads": [
                    {"name": f"LB{idx}", "packets": 0}
                    for idx in range(self.config.num_lbs)
                ],
                "fp_threads": [
                    {"name": f"FP{idx}", "packets": 0}
                    for idx in range(self.config.num_lbs * self.config.fps_per_lb)
                ],
                "recent_packets": [],
                "recent_anomalies": [],
            }

        payload["capture_running"] = running
        payload["rules"] = self.rules_payload()
        payload["last_error"] = last_error
        return payload

    def interfaces_payload(self) -> Dict[str, object]:
        scapy = load_scapy()
        if scapy is None:
            return {"ok": True, "interfaces": [{"name": "simulated"}], "error": ""}

        conf = scapy["conf"]
        get_if_list = scapy["get_if_list"]
        try:
            conf.use_pcap = True
        except Exception:
            pass

        try:
            interfaces = [{"name": iface} for iface in get_if_list()]
            interfaces.append({"name": "simulated"})
        except Exception as exc:
            return {"ok": True, "interfaces": [{"name": "simulated"}], "error": str(exc)}

        return {"ok": True, "interfaces": interfaces, "error": ""}

    def rules_payload(self) -> Dict[str, List[str]]:
        with self.lock:
            return {
                "ips": sorted(self.rule_ips),
                "apps": sorted(self.rule_apps),
                "domains": sorted(self.rule_domains),
            }

    @staticmethod
    def _resolve_domain_rule_ips(domain: str) -> List[str]:
        import socket

        domains_to_resolve = [domain]
        if not domain.startswith("www."):
            domains_to_resolve.append("www." + domain)

        resolved_ips: set[str] = set()
        for dom in domains_to_resolve:
            try:
                resolved = socket.getaddrinfo(dom, None)
            except Exception:
                continue
            for item in resolved:
                resolved_ips.add(item[4][0])
        return sorted(resolved_ips)

    def add_rule(self, rule_type: str, value: str) -> Tuple[bool, str]:
        value = value.strip()
        if not value:
            return False, "Rule value is required"

        if rule_type == "app":
            app_type = Rules.app_from_name(value)
            if app_type is None:
                return False, f"Unknown app: {value}"
            value = app_type_to_string(app_type)

        with self.lock:
            if rule_type == "ip":
                self.rule_ips.add(value)
            elif rule_type == "app":
                self.rule_apps.add(value)
            elif rule_type == "domain":
                self.rule_domains.add(value)
            else:
                return False, "Rule type must be ip, app, or domain"

            engine = self.active_engine

        if engine is not None:
            if rule_type == "ip":
                engine.block_ip(value)
            elif rule_type == "app":
                engine.block_app(value)
            elif rule_type == "domain":
                engine.block_domain(value)

        if rule_type == "domain":
            resolved_ips = self._resolve_domain_rule_ips(value)
            if resolved_ips:
                with self.lock:
                    self.rule_ips.update(resolved_ips)
                    engine = self.active_engine
                if engine is not None:
                    for ip in resolved_ips:
                        engine.block_ip(ip)

        return True, "Rule added"

    def remove_rule(self, rule_type: str, value: str) -> Tuple[bool, str]:
        value = value.strip()
        if not value:
            return False, "Rule value is required"

        with self.lock:
            if rule_type == "ip":
                self.rule_ips.discard(value)
            elif rule_type == "app":
                app_type = Rules.app_from_name(value)
                if app_type is not None:
                    value = app_type_to_string(app_type)
                self.rule_apps.discard(value)
            elif rule_type == "domain":
                self.rule_domains.discard(value)
            else:
                return False, "Rule type must be ip, app, or domain"

            engine = self.active_engine

        if engine is not None:
            if rule_type == "ip":
                engine.unblock_ip(value)
            elif rule_type == "app":
                engine.unblock_app(value)
            elif rule_type == "domain":
                engine.unblock_domain(value)

        if rule_type == "domain":
            resolved_ips = self._resolve_domain_rule_ips(value)
            if resolved_ips:
                with self.lock:
                    for ip in resolved_ips:
                        self.rule_ips.discard(ip)
                    engine = self.active_engine
                if engine is not None:
                    for ip in resolved_ips:
                        engine.unblock_ip(ip)

        return True, "Rule removed"

    def start_live_capture(
        self,
        output_file: str,
        iface: Optional[str],
        duration: Optional[float],
        packet_count: int,
        bpf_filter: Optional[str],
    ) -> Tuple[bool, str]:
        output_file = output_file.strip() or "live_output.pcap"
        if packet_count < 0:
            return False, "Packet count must be zero or positive"
        if duration is not None and duration <= 0:
            return False, "Duration must be positive"

        with self.lock:
            if self.capture_thread is not None and self.capture_thread.is_alive():
                return False, "Live capture is already running"

            engine = DPIEngine(self.config)
            for ip in sorted(self.rule_ips):
                engine.block_ip(ip)
            for app in sorted(self.rule_apps):
                engine.block_app(app)
            for domain in sorted(self.rule_domains):
                engine.block_domain(domain)

            stop_event = threading.Event()
            self.active_engine = engine
            self.stop_event = stop_event
            self.last_error = ""

        def run_capture() -> None:
            ok = engine.process_live(
                output_file=output_file,
                iface=iface or None,
                duration=duration,
                packet_count=packet_count,
                bpf_filter=bpf_filter or None,
                stop_event=stop_event,
            )
            if not ok:
                with self.lock:
                    self.last_error = "Live capture failed. Check terminal output."

        thread = threading.Thread(target=run_capture, name="DashboardLiveCapture")
        thread.daemon = True

        with self.lock:
            self.capture_thread = thread

        thread.start()
        return True, "Live capture started"

    def stop_live_capture(self) -> Tuple[bool, str]:
        with self.lock:
            if self.capture_thread is None or not self.capture_thread.is_alive():
                return False, "No live capture is running"
            stop_event = self.stop_event

        if stop_event is not None:
            stop_event.set()

        return True, "Stopping live capture"

    def shutdown(self) -> None:
        with self.lock:
            thread = self.capture_thread
            stop_event = self.stop_event
        if stop_event is not None:
            stop_event.set()
        if thread is not None and thread.is_alive():
            thread.join(timeout=5)


class DashboardServer:
    def __init__(self, engine: object, host: str, port: int) -> None:
        self.engine = engine
        self.host = host
        self.port = port
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self) -> None:
        engine = self.engine

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                # 1. API Endpoints
                if self.path == "/api/stats":
                    payload = json.dumps(engine.dashboard_payload()).encode("utf-8")
                    self._send_bytes(payload, "application/json; charset=utf-8")
                    return
                if self.path == "/api/interfaces":
                    if hasattr(engine, "interfaces_payload"):
                        payload = engine.interfaces_payload()
                    else:
                        payload = {"ok": False, "interfaces": [], "error": "Dashboard control mode is not active"}
                    self._send_json(payload)
                    return
                if self.path == "/api/rules":
                    if hasattr(engine, "rules_payload"):
                        payload = {"ok": True, "rules": engine.rules_payload()}
                    else:
                        payload = {"ok": False, "rules": {"ips": [], "apps": [], "domains": []}}
                    self._send_json(payload)
                    return

                # 2. Serve static files from Next.js export (dashboard/out)
                import mimetypes
                
                clean_path = self.path.split("?")[0]
                if clean_path == "/":
                    clean_path = "/index.html"
                
                base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                out_dir = os.path.join(base_dir, "dashboard", "out")
                file_path = os.path.join(out_dir, clean_path.lstrip("/"))
                
                # Check bounds to prevent directory traversal
                norm_file_path = os.path.abspath(file_path)
                norm_out_dir = os.path.abspath(out_dir)
                
                if norm_file_path.startswith(norm_out_dir) and os.path.exists(norm_file_path) and os.path.isfile(norm_file_path):
                    # Force correct MIME types to bypass corrupt Windows Registry mappings
                    if norm_file_path.endswith(".css"):
                        mime_type = "text/css"
                    elif norm_file_path.endswith(".js"):
                        mime_type = "application/javascript"
                    elif norm_file_path.endswith(".html"):
                        mime_type = "text/html; charset=utf-8"
                    elif norm_file_path.endswith(".svg"):
                        mime_type = "image/svg+xml"
                    elif norm_file_path.endswith(".ico"):
                        mime_type = "image/x-icon"
                    elif norm_file_path.endswith(".png"):
                        mime_type = "image/png"
                    elif norm_file_path.endswith(".jpg") or norm_file_path.endswith(".jpeg"):
                        mime_type = "image/jpeg"
                    else:
                        mime_type, _ = mimetypes.guess_type(norm_file_path)
                        if not mime_type:
                            mime_type = "application/octet-stream"
                    try:
                        with open(norm_file_path, "rb") as f:
                            self._send_bytes(f.read(), mime_type)
                        return
                    except Exception:
                        pass

                # 3. Fallback to hardcoded DASHBOARD_HTML if Next.js export file is missing
                if self.path == "/" or self.path.startswith("/?"):
                    self._send_bytes(DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")
                    return
                    
                self.send_error(404)

            def do_POST(self) -> None:
                data = self._read_json()
                if self.path == "/api/rules":
                    if not hasattr(engine, "add_rule"):
                        self._send_json({"ok": False, "message": "Rule controls are not active"}, 400)
                        return
                    ok, message = engine.add_rule(str(data.get("type", "")), str(data.get("value", "")))
                    self._send_json({"ok": ok, "message": message, "rules": engine.rules_payload()}, 200 if ok else 400)
                    return
                if self.path == "/api/live/start":
                    if not hasattr(engine, "start_live_capture"):
                        self._send_json({"ok": False, "message": "Live controls are not active"}, 400)
                        return
                    try:
                        duration_raw = data.get("duration")
                        duration = None
                        if duration_raw not in (None, ""):
                            duration = float(duration_raw)
                        count_raw = data.get("count", 0)
                        packet_count = int(count_raw) if count_raw not in (None, "") else 0
                    except (TypeError, ValueError):
                        self._send_json({"ok": False, "message": "Duration/count must be numeric"}, 400)
                        return
                    ok, message = engine.start_live_capture(
                        output_file=str(data.get("output_file", "live_output.pcap")),
                        iface=str(data.get("iface", "")).strip() or None,
                        duration=duration,
                        packet_count=packet_count,
                        bpf_filter=str(data.get("bpf", "")).strip() or None,
                    )
                    self._send_json({"ok": ok, "message": message}, 200 if ok else 400)
                    return
                if self.path == "/api/live/stop":
                    if not hasattr(engine, "stop_live_capture"):
                        self._send_json({"ok": False, "message": "Live controls are not active"}, 400)
                        return
                    ok, message = engine.stop_live_capture()
                    self._send_json({"ok": ok, "message": message}, 200 if ok else 400)
                    return
                self.send_error(404)

            def do_DELETE(self) -> None:
                data = self._read_json()
                if self.path == "/api/rules":
                    if not hasattr(engine, "remove_rule"):
                        self._send_json({"ok": False, "message": "Rule controls are not active"}, 400)
                        return
                    ok, message = engine.remove_rule(str(data.get("type", "")), str(data.get("value", "")))
                    self._send_json({"ok": ok, "message": message, "rules": engine.rules_payload()}, 200 if ok else 400)
                    return
                self.send_error(404)

            def do_OPTIONS(self) -> None:
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")
                self.end_headers()

            def _send_bytes(self, payload: bytes, content_type: str) -> None:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(payload)

            def _send_json(self, payload: Dict[str, object], status: int = 200) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

            def _read_json(self) -> Dict[str, object]:
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length <= 0:
                    return {}
                body = self.rfile.read(length)
                try:
                    parsed = json.loads(body.decode("utf-8"))
                except json.JSONDecodeError:
                    return {}
                return parsed if isinstance(parsed, dict) else {}

            def log_message(self, format: str, *args: object) -> None:
                return

        self.httpd = ThreadingHTTPServer((self.host, self.port), Handler)
        self.host, self.port = self.httpd.server_address
        self.thread = threading.Thread(target=self.httpd.serve_forever, name="DashboardServer")
        self.thread.daemon = True
        self.thread.start()

    def stop(self) -> None:
        if self.httpd is not None:
            self.httpd.shutdown()
            self.httpd.server_close()
        if self.thread is not None:
            self.thread.join()

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"
