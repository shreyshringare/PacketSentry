# Design: PacketSentry UI/UX Overhaul — Stark Industries Cyber-Industrial Redesign

**Date:** 2026-05-19  
**Status:** APPROVED  
**Scope:** Presentation layer only — zero changes to state, hooks, API, or virtualization

---

## Problem Statement

PacketSentry's web dashboard uses a soft SaaS aesthetic (rounded cards, `shadow-sm`, blue accents, `bg-gray-50`) that undersells the project's industrial/security nature. The redesign pivots to a **Stark Industries + Neo-Brutalist + Cyber-Industrial** visual identity that matches the project's technical depth and makes a stronger first impression for ML/AI and Security/Infra roles.

---

## Design Principles

- **Stark Industries:** Utilitarian, corporate-militaristic, high contrast (black / industrial silver / stark white)
- **Neo-Brutalist:** Zero rounded corners, thick solid black borders, hard flat offset shadows
- **Retro Terminal:** Phosphorus green (`#00FF41`) strictly for active states, CRT scanline overlays, monospace data feeds

---

## Section 1: Design Tokens & Global Styles

### `tailwind.config.js`

```javascript
theme: {
  extend: {
    colors: {
      industrial: { canvas: "#C0C0C0", steel: "#E4E4E7" },
      pixel: { green: "#00FF41" }
    },
    boxShadow: {
      brutalist: "4px 4px 0px 0px rgba(0,0,0,1)"
    },
    borderRadius: {
      none: "0px"
    }
  }
}
```

### `src/index.css`

```css
body {
  font-family: 'Space Grotesk', 'Inter', sans-serif;
  background-color: #C0C0C0;
}

/* CRT scanline overlay — apply to packet stream container */
.crt-scanlines {
  position: relative;
  overflow: hidden;
}
.crt-scanlines::after {
  content: " ";
  display: block;
  position: absolute;
  top: 0; left: 0; bottom: 0; right: 0;
  background: linear-gradient(rgba(18,16,16,0) 50%, rgba(0,0,0,0.2) 50%);
  background-size: 100% 4px;
  pointer-events: none;
  z-index: 10;
}

/* Terminal blinking cursor — apply to empty-state elements */
.terminal-cursor::after {
  content: " _";
  animation: blink 1s step-start infinite;
}

@keyframes blink {
  50% { opacity: 0; }
}
```

---

## Section 2: Component-by-Component Spec

### `App.tsx`
- Root div: `bg-[#C0C0C0]` (was `bg-gray-50`)
- Add Stark Industries footer above closing tag:
```tsx
<footer className="h-6 border-t-2 border-black bg-white flex items-center justify-between px-4 text-[9px] text-gray-400 select-none shrink-0 font-medium tracking-wide">
  <div>SYSTEM STATUS: SECURE // SENTRY CORE ONLINE</div>
  <div className="flex items-center gap-1.5">
    <span className="font-bold text-[8.5px] text-gray-500 tracking-wider">STARK INDUSTRIES</span>
    <span className="text-gray-300">|</span>
    <span className="italic tracking-widest text-[8px]">CHANGING THE WORLD FOR A BETTER FUTURE</span>
  </div>
</footer>
```

### `TopNav.tsx`
- Header: `bg-white border-b-2 border-black` (was `border-gray-200`)
- Logo area: add "STARK INDUSTRIES" subtitle in `text-[7.5px] font-bold text-gray-400 tracking-widest uppercase`
- PixelShield icon: `text-gray-900` (was `text-blue-600`)
- Active tab: `bg-black text-[#00FF41] border-2 border-black rounded-none px-3 py-1 text-xs font-bold uppercase tracking-wide`
- Inactive tab: `bg-transparent text-gray-600 border-2 border-transparent hover:border-black hover:text-black rounded-none`
- Live indicator dot: keep `animate-pulse`, change to `bg-[#00FF41]` when running (was `bg-green-500`)
- Status text: `font-mono text-xs font-bold` when running: `text-[#00FF41]`

### `StatCards.tsx`

Card container:
- Remove `rounded-lg`, add `rounded-none`
- Remove `shadow-sm hover:shadow-md transition-shadow`
- Add `border-2 border-black shadow-brutalist`
- Background: `bg-white`

Card value:
- `text-3xl font-black` (was `text-2xl font-bold`)

Icon container:
- Remove `rounded-lg`, add `rounded-none`
- Background: `bg-black` always (was accent-colored)
- Icon color: `text-white` always (was accent-colored)

Accent colors for value text: unchanged (`text-red-600`, `text-amber-500`, `text-green-600`, `text-gray-900`)

### `LiveCapture.tsx`

Toolbar container:
- `rounded-none border-2 border-black bg-white` (was `rounded-lg border-gray-200`)

Interface `<select>` → replace with custom dropdown:
```tsx
// Custom dropdown trigger — styled command-line input
<div className="relative">
  <button className="text-xs border-2 border-black px-2 py-1.5 bg-white font-mono flex items-center gap-1 hover:bg-black hover:text-white transition-colors duration-100">
    {iface} <span className="text-[10px]">▼</span>
  </button>
  {/* Dropdown list — black border, hard shadow, color-invert on hover */}
  {dropdownOpen && (
    <div className="absolute top-full left-0 z-50 border-2 border-black bg-white shadow-brutalist">
      {INTERFACES.map(i => (
        <div key={i}
          onClick={() => { setInterface(i); setDropdownOpen(false); }}
          className="px-3 py-1.5 text-xs font-mono cursor-pointer hover:bg-black hover:text-white"
        >
          {i}
        </div>
      ))}
    </div>
  )}
</div>
```
Requires `const [dropdownOpen, setDropdownOpen] = useState(false)` — this is UI-only state, not business logic.

Protocol toggle buttons:
- Active: `bg-black text-[#00FF41] border-2 border-black rounded-none`
- Inactive: `bg-white text-gray-700 border-2 border-black rounded-none hover:bg-black hover:text-white`

BPF filter input — terminal prompt wrapper:
```tsx
<div className="flex-1 min-w-32 flex items-center border-2 border-black bg-black px-2 py-1.5">
  <span className="text-[#00FF41] font-mono text-xs shrink-0 mr-1">root@packetsentry:~$</span>
  <input
    className="flex-1 bg-transparent text-[#00FF41] font-mono text-xs outline-none placeholder-gray-600"
    placeholder="port 80 or port 443"
    value={bpfFilter}
    onChange={(e) => setBpfFilter(e.target.value)}
    disabled={running}
  />
</div>
```

Start button: `bg-black text-[#00FF41] border-2 border-black rounded-none font-bold uppercase tracking-wide text-xs px-3 py-1.5 hover:bg-[#00FF41] hover:text-black`  
Stop button: `bg-white text-red-600 border-2 border-red-600 rounded-none font-bold uppercase tracking-wide text-xs px-3 py-1.5 hover:bg-red-600 hover:text-white`

Threat Radar panel: `rounded-none border-2 border-black bg-white shadow-brutalist`

### `PacketStream.tsx`

Outer container:
- Add `.crt-scanlines` class
- `rounded-none border-2 border-black` (was `rounded-lg border-gray-800`)

Header row: `border-b-2 border-gray-700 text-[#00FF41] font-mono font-bold`

Row flag badges: `bg-[#00FF41] text-black font-bold px-1` (was `bg-gray-800 text-gray-300`)

Flagged row: `text-red-500` — unchanged  
Suspicious row: `text-amber-500` — unchanged  
Normal row: `text-gray-400` — unchanged  

**Virtualization invariants — DO NOT TOUCH:**
- `<List>` props: `rowCount`, `rowHeight={ITEM_HEIGHT}`, `rowComponent={Row}`, `rowProps={{ packets }}`, `listRef`
- `ITEM_HEIGHT = 22`, `MAX_VISIBLE = 20`
- Row `style` prop passthrough

### `Settings.tsx`

Page container: `bg-[#C0C0C0]`

Each `<section>`:
- `rounded-none border-2 border-black bg-white shadow-brutalist` (was `rounded-lg border-gray-200`)
- Section headers: `font-black uppercase tracking-wide text-sm border-b-2 border-black pb-2 mb-3`

Inputs: `rounded-none border-2 border-black focus:border-[#00FF41] focus:outline-none bg-white font-mono text-xs px-2 py-1.5`

Range sliders — custom CSS class `.fader-input`:
```css
.fader-input {
  -webkit-appearance: none;
  appearance: none;
  height: 4px;
  background: #000;
  outline: none;
}
.fader-input::-webkit-slider-thumb {
  -webkit-appearance: none;
  appearance: none;
  width: 12px;
  height: 20px;
  background: #000;
  cursor: pointer;
  border: 2px solid #000;
  border-radius: 0;
}
.fader-input::-webkit-slider-thumb:hover {
  background: #00FF41;
}
```

Save button: `rounded-none border-2 border-black bg-black text-[#00FF41] font-bold uppercase tracking-wide px-4 py-2 hover:bg-[#00FF41] hover:text-black`  
Saved state: `bg-[#00FF41] text-black border-2 border-black`

Normalize button: same brutalist style as Save.

### `Overview.tsx`

Page panels: `rounded-none border-2 border-black bg-white shadow-brutalist` (all occurrences of `rounded-lg border-gray-200`)

Section headers: `border-b-2 border-black font-black uppercase tracking-wide text-xs`

### `AlertFeed.tsx`

Empty state:
```tsx
<div className="text-xs font-mono text-gray-500 terminal-cursor">
  &gt; Awaiting threats...
</div>
```

Alert rows: `border-b-2 border-black rounded-none`  
Selected row: `bg-black text-white` (was `bg-blue-50`)  
Transition: `transition-colors duration-100 ease-linear` (remove soft easing)

---

## Section 3: Preserved Invariants

These are **read-only** for this phase — zero modifications:

| File | What to preserve |
|------|-----------------|
| `store/captureStore.ts` | All state + actions |
| `store/alertStore.ts` | All state + actions |
| `store/uiStore.ts` | All state + actions |
| `hooks/useWebSocket.ts` | Entire file |
| `api/client.ts` | Entire file |
| `PacketStream.tsx` | `<List>` props, `ITEM_HEIGHT`, `MAX_VISIBLE`, Row render logic, `style` passthrough |
| `LiveCapture.tsx` | `handleStart`, `handleStop`, `useCaptureStore` bindings, `useAlertStore` bindings |
| `Settings.tsx` | `handleSave`, all `useState` hooks, `normalize()` |

---

## Execution Order

1. `tailwind.config.js` + `src/index.css` — tokens land first
2. `App.tsx` — canvas bg + Stark footer
3. `TopNav.tsx` — terminal tabs + Stark co-brand
4. `StatCards.tsx` — brutalist cards
5. `LiveCapture.tsx` — terminal prompt + custom dropdown + proto toggles
6. `PacketStream.tsx` — CRT wrapper + flag highlights
7. `Settings.tsx` — hardware panels + fader CSS
8. `Overview.tsx` — panel wrappers
9. `AlertFeed.tsx` — terminal cursor empty state + row styles

---

## Success Criteria

- App canvas is `#C0C0C0` brushed-steel gray
- Zero rounded corners anywhere in the UI
- All card/panel borders are `border-2 border-black`
- Active nav tab: black bg, pixel-green text
- BPF input shows `root@packetsentry:~$` terminal prompt
- Packet stream has CRT scanline overlay
- Settings sliders have flat black knob style
- Stark Industries footer visible on all screens
- All 241 tests still pass (no logic touched)
- `react-window` List renders correctly at same item heights
