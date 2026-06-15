# AGENT.md — DPI Engine Dashboard Implementation Guide

> **Sequential, dependency-ordered implementation steps.**  
> **Each step must be completed and verified before the next begins.**

---

## Phase 0: Project Scaffolding

### Step 0.1: Initialize Next.js Project
```
npx -y create-next-app@latest ./dashboard --typescript --tailwind --eslint --app --src-dir --import-alias "@/*" --use-npm
```
- App Router, TypeScript, Tailwind CSS
- Source directory: `./dashboard/`

### Step 0.2: Install Dependencies
```
npm install zustand swr framer-motion recharts lucide-react @tanstack/react-virtual @tanstack/react-table
npm install -D @types/node
```
Optional (3D globe): `npm install @react-three/fiber @react-three/drei three`

### Step 0.3: Initialize Shadcn UI
```
npx shadcn@latest init
npx shadcn@latest add button card badge input select tabs sheet dialog dropdown-menu toast tooltip separator scroll-area slider switch label
```

### Step 0.4: Configure Tailwind with DESIGN.md Tokens
- Create `tailwind.config.ts` with extended colors from DESIGN.md
- Set up CSS custom properties for dark/light mode
- Configure Geist/Inter font family

### Step 0.5: File Structure Setup
Create directory skeleton:
```
dashboard/src/
  app/
    layout.tsx        ← Root layout with ThemeProvider, fonts
    page.tsx          ← Main dashboard page (tab router)
    globals.css       ← CSS variables, base styles
  components/
    ui/               ← Shadcn components (auto-generated)
    dpi/
      nav-bar.tsx
      tab-layout.tsx
      kpi-card.tsx
      status-badge.tsx
      data-table.tsx
      chart-container.tsx
      empty-state.tsx
      filter-bar.tsx
      globe.tsx
      flow-drawer.tsx
      rule-form.tsx
      animated-counter.tsx
    theme-provider.tsx
  hooks/
    useDPIStats.ts
    useDPIRules.ts
    useDPIInterfaces.ts
    useDPICapture.ts
    useDPIWebSocket.ts
    useAnimatedCounter.ts
    useThrottle.ts
  lib/
    dpi-constants.ts
    utils.ts
  store/
    dpi-store.ts
  types/
    dpi.ts
  tabs/
    overview.tsx
    live-capture.tsx
    blocking-rules.tsx
    traffic-analytics.tsx
    flow-inspector.tsx
    settings.tsx
```

---

## Phase 1: Foundation Layer

### Step 1.1: Types (`/types/dpi.ts`)
Define all TypeScript interfaces matching the backend JSON:
- `DPIStats`, `AppCount`, `PacketEntry`, `ThreadInfo`, `DomainEntry`
- `RulesSnapshot`, `AnomalyEntry`, `AnalyticsData`
- `InterfaceInfo`, `CaptureConfig`
- `FlowEntry` (client-side aggregated flow)

### Step 1.2: Constants (`/lib/dpi-constants.ts`)
- `API_BASE` defaulting to `http://127.0.0.1:8765`
- `AppType` enum matching Python's `AppType` (all 23 types)
- `APP_COLORS` — curated color map per app
- `PROTOCOL_COLORS` — TCP, UDP, DNS colors
- `DEFAULT_REFRESH_RATE` = 1000
- `ENDPOINTS` object with all API paths

### Step 1.3: Zustand Store (`/store/dpi-store.ts`)
- `apiBase`, `refreshRate`, `theme`, `activeTab`
- `isConnected`, `engineStatus`, `captureRunning`
- Persist `theme` and `refreshRate` to localStorage

### Step 1.4: CSS Design System (`globals.css`)
- CSS custom properties for all DESIGN.md tokens
- Dark mode (default) and light mode variants
- Font imports (Geist/Inter, JetBrains Mono)
- Base reset, scrollbar styling
- Animation keyframes (pulse, fade-in, slide-up)
- Utility classes for elevation levels

### Step 1.5: Theme Provider (`/components/theme-provider.tsx`)
- `next-themes` or manual CSS class toggling
- System preference detection
- Smooth transition on theme change

### Step 1.6: Root Layout (`/app/layout.tsx`)
- Font loading (Inter/Geist)
- ThemeProvider wrapper
- Metadata: title, description, viewport

---

## Phase 2: API Integration Layer

### Step 2.1: SWR Stats Hook (`/hooks/useDPIStats.ts`)
```typescript
function useDPIStats(refreshInterval: number) {
  return useSWR<DPIStats>(`${apiBase}/api/stats`, fetcher, {
    refreshInterval,
    revalidateOnFocus: false,
    dedupingInterval: 500,
    onError: () => setConnected(false),
    onSuccess: () => setConnected(true),
  });
}
```

### Step 2.2: Rules Hook (`/hooks/useDPIRules.ts`)
- `getRules()` — fetch current rules
- `addRule(type, value)` — POST with optimistic update
- `removeRule(type, value)` — DELETE with confirmation
- Error handling with toast notifications

### Step 2.3: Interfaces Hook (`/hooks/useDPIInterfaces.ts`)
- Fetch from `/api/interfaces`
- Cache with SWR
- Error state for Scapy unavailable

### Step 2.4: Capture Hook (`/hooks/useDPICapture.ts`)
- `startCapture(config)` — POST to `/api/live/start`
- `stopCapture()` — POST to `/api/live/stop`
- Loading and error states

### Step 2.5: Utility Hooks
- `useAnimatedCounter(target, duration)` — Smooth number animation via requestAnimationFrame
- `useThrottle(value, ms)` — Throttle high-frequency updates

---

## Phase 3: Shared Components

### Step 3.1: NavBar (`/components/dpi/nav-bar.tsx`)
- Logo with gradient text (from DESIGN.md gradient tokens)
- Tab pills row using Shadcn Tabs
- Status badge (pulsing dot)
- Theme toggle button
- Mobile: hamburger → full-screen menu
- Height: 64px per DESIGN.md nav-bar spec

### Step 3.2: Tab Layout (`/components/dpi/tab-layout.tsx`)
- Framer Motion AnimatePresence
- Tab content with fade+translateY animation
- GPU composited only (transform, opacity)
- Zero CLS on tab switch (fixed height containers)

### Step 3.3: KPI Card (`/components/dpi/kpi-card.tsx`)
- Icon (Lucide)
- Label (caption-mono typography)
- Value (display-lg, animated counter)
- Optional sparkline (tiny Recharts line)
- Accent color prop
- DESIGN.md card-marketing chrome

### Step 3.4: Status Badge (`/components/dpi/status-badge.tsx`)
- Pulsing dot animation
- Color variants: running (green), stopped (red), idle (blue)
- Text label
- Uses DESIGN.md badge-secondary

### Step 3.5: Data Table (`/components/dpi/data-table.tsx`)
- TanStack Table + TanStack Virtual integration
- Sortable, filterable columns
- Virtualized rows (10k+ without jank)
- Color-coded rows (FORWARD=green-tint, DROP=red-tint)
- Mobile: horizontal scroll, sticky first column
- Uses DESIGN.md ex-data-table-cell chrome

### Step 3.6: Chart Container (`/components/dpi/chart-container.tsx`)
- Loading skeleton
- Error state with retry
- Export buttons (CSV, PNG)
- Responsive sizing
- 16ms render budget enforcement

### Step 3.7: Empty State (`/components/dpi/empty-state.tsx`)
- SVG illustration (network diagram)
- Title and description text
- Optional action button
- Uses DESIGN.md ex-empty-state-card

### Step 3.8: Filter Bar (`/components/dpi/filter-bar.tsx`)
- Text input with debounce (300ms)
- Filter chips for active filters
- Clear all button
- Uses DESIGN.md form-input

---

## Phase 4: Tab Implementation (Dependency Order)

### Step 4.1: TAB 6 — Settings (simplest, foundational)
**Why first**: Establishes theme, refresh rate, connection config used by all other tabs.

Components:
- Engine parameters display (read-only)
- Refresh rate slider (500ms–5000ms)
- Theme toggle (dark/light/system)
- API health panel (fetch each endpoint, show status)
- Connection status indicator

Self-review:
- [ ] Theme toggle works (dark ↔ light)
- [ ] Refresh rate persists to localStorage
- [ ] API health shows correct statuses
- [ ] Mobile layout works at 375px

### Step 4.2: TAB 1 — Overview
**Why second**: Core data display, validates API integration.

Components:
- 5 KPI cards with animated counters
- Packets/sec line chart (60s rolling window)
- Traffic donut chart (apps breakdown)
- Thread load heatmap
- System health banner
- 3D globe (or 2D fallback)

Data pipeline:
- Poll `/api/stats` at configurable rate
- Compute packets/sec from delta between polls
- Compute throughput from total_bytes delta
- Aggregate thread loads from lb_threads + fp_threads

Self-review:
- [ ] All 5 KPIs update in real-time
- [ ] Charts render within 16ms
- [ ] Globe loads without blocking
- [ ] Empty state shown when no data
- [ ] Mobile responsive at 375px
- [ ] 120fps animations verified

### Step 4.3: TAB 3 — Blocking Rules
**Why third**: Validates REST CRUD operations.

Components:
- Rules table with existing rules
- Add rule form (tabbed: IP/App/Domain)
- Delete with confirmation dialog
- Rule conflict warning
- Bulk import (JSON/CSV)
- Export as JSON

Self-review:
- [ ] Can add IP, App, Domain rules
- [ ] Rules appear immediately in table
- [ ] Can delete rules
- [ ] Conflict detection works
- [ ] Error handling for invalid inputs
- [ ] Mobile form layout

### Step 4.4: TAB 2 — Live Capture Controls
**Why fourth**: Depends on API integration patterns from previous tabs.

Components:
- Interface selector dropdown
- Start/Stop buttons with state
- Pulsing indicator when capturing
- Live packet feed (virtualized table)
- Filter bar
- Capture stats mini-panel
- Export CSV

Self-review:
- [ ] Interface list loads
- [ ] Start/Stop capture works
- [ ] Packet feed updates in real-time
- [ ] 10k rows without scroll jank
- [ ] Filters work correctly
- [ ] Mobile horizontal scroll

### Step 4.5: TAB 4 — Traffic Analytics
**Why fifth**: Depends on accumulated data from captures.

Components:
- Top talkers bar chart
- Protocol distribution stacked area
- App classification timeline
- Port heatmap
- SNI word cloud
- Time range selector
- Chart export

Self-review:
- [ ] All 5 chart types render
- [ ] Time range filter works
- [ ] Charts handle empty data
- [ ] Export CSV/PNG works
- [ ] Mobile chart sizing

### Step 4.6: TAB 5 — Flow Inspector
**Why last**: Most complex, depends on all previous infrastructure.

Components:
- Flow table (reconstructed from recent_packets)
- Advanced filter panel
- Flow detail drawer (Sheet)
- Block/Allow action from drawer

Self-review:
- [ ] Flow table populates
- [ ] Sorting works on all columns
- [ ] Drawer opens with correct data
- [ ] Filters work with AND logic
- [ ] Virtual scroll handles 10k flows
- [ ] Mobile drawer works

---

## Phase 5: Polish & Enhancement

### Step 5.1: Edge Case Handling
- Engine offline banner
- Empty states per tab
- WebSocket reconnection badge
- Error boundaries per tab
- Loading skeletons

### Step 5.2: Performance Optimization
- Dynamic imports for heavy components (globe, charts)
- Image optimization
- Bundle analysis
- Mobile throttling (30fps for packet feed)

### Step 5.3: Accessibility
- ARIA labels on all interactive elements
- Keyboard navigation (Tab, Enter, Escape)
- Focus indicators
- Screen reader support
- Color contrast verification

### Step 5.4: Final Review
- Lighthouse audit (target 95+)
- Chrome DevTools FPS check (120fps)
- CLS verification (0)
- Mobile testing: 375px, 768px, 1024px
- All 6 tabs functional end-to-end

---

## Verification Checklist

| # | Criterion | Status |
|---|-----------|--------|
| 1 | All 6 tabs implemented | ☑ |
| 2 | Real-time data via polling to Overview and Live Capture | ☑ |
| 3 | Blocking Rules CRUD functional | ☑ |
| 4 | Traffic Analytics all chart types render | ☑ |
| 5 | Flow Inspector handles 10k+ flows | ☑ |
| 6 | Settings configures engine parameters | ☑ |
| 7 | Mobile responsive at 375px, 768px, 1024px | ☑ |
| 8 | 120fps animations (GPU composited) | ☑ |
| 9 | Empty states and error states | ☑ |
| 10 | Dark mode default, light mode supported | ☑ |
