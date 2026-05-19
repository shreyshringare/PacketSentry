
interface PixelIconProps {
  className?: string;
  size?: number;
}

/**
 * Premium retro-cyberpunk Pixel Art SVGs in the style of Streamline Pixel.
 * Hand-drawn mathematical grids utilizing browser shape-rendering for crisp, pixel-perfect edges.
 */

export function PixelShield({ className = "text-gray-900", size = 24 }: PixelIconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      shapeRendering="crispEdges"
      fill="none"
    >
      {/* Accent Blue Shield Fill */}
      <path
        d="M6 4h12v4H6V4zm2 4h8v2H8V8zm-2 2h12v4H6v-4zm2 4h8v2H8v-2zm2 2h4v2h-4v-2z"
        fill="#3b82f6"
        fillOpacity="0.2"
      />
      {/* Dynamic Inner detail */}
      <path d="M11 5h2v12h-2V5z" fill="#3b82f6" fillOpacity="0.4" />
      {/* Sharp Black Outlines */}
      <path
        d="M4 2h16v2H4V2zm-2 2h2v6H2V4zm18 0h2v6h-2V4zM2 10h2v4H2v-4zm18 0h2v4h-2v-4zm-2 4h2v2h-2v-2zm-14 0h-2v2h2v-2zm2 2h-2v2h2v-2zm10 0h2v2h-2v-2zm-8 2h-2v2h2v-2zm6 0h2v2h-2v-2zm-4 2h2v2h-2v-2z"
        fill="currentColor"
      />
    </svg>
  );
}

export function PixelConsole({ className = "text-gray-900", size = 24 }: PixelIconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      shapeRendering="crispEdges"
      fill="none"
    >
      {/* Screen Neon Green Fill */}
      <path d="M4 4h16v12H4V4z" fill="#10b981" fillOpacity="0.1" />
      {/* Cursor & Prompt */}
      <path d="M6 6h2v2H6V6zm4 6h4v2h-4v-2z" fill="#10b981" />
      {/* Frame / Bezel */}
      <path
        d="M2 2h20v2H2V2zm0 2h2v12H2V4zm18 0h2v12h-2V4zM2 16h20v2H2v-2zm-2 2h24v4H0v-4zm4 2h16v2H4v-2z"
        fill="currentColor"
      />
    </svg>
  );
}

export function PixelAlert({ className = "text-gray-900", size = 24 }: PixelIconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      shapeRendering="crispEdges"
      fill="none"
    >
      {/* Red Siren/Bell Fill */}
      <path
        d="M10 4h4v2h-4V4zm-2 2h8v2H8V6zm-2 2h12v8H6V8zm-2 8h16v2H4v-2z"
        fill="#ef4444"
        fillOpacity="0.2"
      />
      {/* White Siren Glow */}
      <path d="M12 6h2v6h-2V6z" fill="#ef4444" fillOpacity="0.6" />
      {/* Outlines */}
      <path
        d="M9 2h6v2H9V2zM7 4h2v2H7V4zm8 0h2v2h-2V4zM5 6h2v2H5V6zm12 0h2v2h-2V6zM3 8h2v8H3V8zm16 0h2v8h-2V8zM1 16h2v2H1v-2zm20 0h2v2h-2v-2zm-18 2h18v2H3v-2zm6 2h6v2H9v-2z"
        fill="currentColor"
      />
    </svg>
  );
}

export function PixelSettings({ className = "text-gray-900", size = 24 }: PixelIconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      shapeRendering="crispEdges"
      fill="none"
    >
      {/* Core cog fill */}
      <path d="M8 8h8v8H8V8z" fill="#6b7280" fillOpacity="0.2" />
      {/* Cog outlines with teeth */}
      <path
        d="M10 2h4v3h-4V2zm-4 4h2v2H6V6zm12 0h-2v2h2V6zm-13 4h3v4H5v-4zm14 0h3v4h-3v-4zm-13 4h2v2H6v-2zm12 0h-2v2h2v-2zm-8 4h4v2h-4v-2z"
        fill="currentColor"
      />
      <path
        d="M8 8h2v2H8V8zm6 0h2v2h-2V8zm-6 6h2v2H8v-2zm6 0h2v2h-2v-2z"
        fill="currentColor"
      />
    </svg>
  );
}

export function PixelPulse({ className = "text-gray-900", size = 24 }: PixelIconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      shapeRendering="crispEdges"
      fill="none"
    >
      {/* Pulse line in Neon Green */}
      <path
        d="M2 11h4v2H2v-2zm4-2h2v2H6V9zm2-4h2v4H8V5zm2 12h2v2h-2v-2zm2-6h2v6h-2v-6zm2-4h2v4h-2V7zm2 4h2v2h-2v-2zm2-2h4v2h-4V9z"
        fill="currentColor"
      />
    </svg>
  );
}

export function PixelBranch({ className = "text-gray-900", size = 24 }: PixelIconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      width={size}
      height={size}
      className={className}
      shapeRendering="crispEdges"
      fill="none"
    >
      {/* Multi-branch nodes */}
      {/* Top Root node */}
      <path d="M10 2h4v4h-4V2zm1 1h2v2h-2V3z" fill="currentColor" />
      {/* Left Leaf Node */}
      <path d="M4 16h4v4H4v-4zm1 1h2v2H5v-2z" fill="currentColor" />
      {/* Right Leaf Node */}
      <path d="M16 16h4v4h-4v-4zm1 1h2v2h-2v-2z" fill="currentColor" />
      {/* Branch links */}
      <path d="M11 6h2v6h-2V6zm-5 6h12v2H6v-2zm0 2h2v2H6v-2zm10 0h2v2h-2v-2z" fill="#3b82f6" />
    </svg>
  );
}
