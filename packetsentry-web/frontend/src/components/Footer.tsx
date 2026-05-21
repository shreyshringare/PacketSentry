// packetsentry-web/frontend/src/components/Footer.tsx

const YEAR = new Date().getFullYear();

interface FooterProps {
  /** "dashboard" renders a single slim bar; "landing" renders a two-row footer */
  variant?: "dashboard" | "landing";
}

export function Footer({ variant = "landing" }: FooterProps) {
  if (variant === "dashboard") {
    return (
      <footer className="shrink-0 border-t-2 border-black bg-black px-4 py-1 flex items-center justify-between gap-4">
        <span className="font-mono text-[8px] text-gray-500 tracking-wide">
          © {YEAR} PacketSentry · Authorized use only · Network monitoring may be subject to local laws
        </span>
        <div className="flex items-center gap-4">
          <a
            href="/privacy"
            className="font-mono text-[8px] text-gray-500 hover:text-[#00FF41] transition-colors tracking-wide"
          >
            Privacy
          </a>
          <span className="text-gray-700 text-[8px]">|</span>
          <a
            href="/terms"
            className="font-mono text-[8px] text-gray-500 hover:text-[#00FF41] transition-colors tracking-wide"
          >
            Terms
          </a>
          <span className="text-gray-700 text-[8px]">|</span>
          <a
            href="/disclaimer"
            className="font-mono text-[8px] text-gray-500 hover:text-[#00FF41] transition-colors tracking-wide"
          >
            Legal Disclaimer
          </a>
        </div>
      </footer>
    );
  }

  return (
    <footer className="shrink-0 border-t-2 border-black bg-black">
      {/* Top row */}
      <div className="px-6 py-3 flex items-center justify-between border-b border-gray-800">
        <span className="font-mono text-[9px] text-[#00FF41] tracking-widest uppercase">
          PacketSentry // NIDS v1.0
        </span>
        <div className="flex items-center gap-5">
          <a
            href="/privacy"
            className="font-mono text-[9px] text-gray-400 hover:text-[#00FF41] transition-colors tracking-wide uppercase"
          >
            Privacy Policy
          </a>
          <a
            href="/terms"
            className="font-mono text-[9px] text-gray-400 hover:text-[#00FF41] transition-colors tracking-wide uppercase"
          >
            Terms of Use
          </a>
          <a
            href="/disclaimer"
            className="font-mono text-[9px] text-gray-400 hover:text-[#00FF41] transition-colors tracking-wide uppercase"
          >
            Legal Disclaimer
          </a>
        </div>
      </div>
      {/* Bottom row */}
      <div className="px-6 py-2 flex items-center justify-between">
        <span className="font-mono text-[8px] text-gray-600 tracking-wide">
          © {YEAR} PacketSentry. All rights reserved.
        </span>
        <span className="font-mono text-[8px] text-gray-600 tracking-wide text-right max-w-md">
          For authorized network monitoring only. Unauthorized interception of network traffic may violate applicable laws including the CFAA, ECPA, and GDPR.
        </span>
      </div>
    </footer>
  );
}
