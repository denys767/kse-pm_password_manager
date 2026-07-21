import type { SVGProps } from 'react';

/** Shared stroke-based icon set — replaces emoji/unicode glyphs across the UI. */
function Svg(props: SVGProps<SVGSVGElement>) {
    return <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props} />;
}

export function IconVault(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M3 10.5 12 4l9 6.5" /><path d="M5 9.5V20h14V9.5" /><path d="M9 20v-6h6v6" /></Svg>;
}
export function IconDashboard(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><rect x="3" y="3" width="8" height="8" rx="1.5" /><rect x="13" y="3" width="8" height="5" rx="1.5" /><rect x="13" y="12" width="8" height="9" rx="1.5" /><rect x="3" y="15" width="8" height="6" rx="1.5" /></Svg>;
}
export function IconCollections(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><rect x="3" y="3" width="7" height="7" rx="1.2" /><rect x="14" y="3" width="7" height="7" rx="1.2" /><rect x="3" y="14" width="7" height="7" rx="1.2" /><rect x="14" y="14" width="7" height="7" rx="1.2" /></Svg>;
}
export function IconActivity(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3.5 2" /></Svg>;
}
export function IconSettings(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .34 1.87l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.7 1.7 0 0 0-1.87-.34 1.7 1.7 0 0 0-1.04 1.56V21a2 2 0 1 1-4 0v-.09a1.7 1.7 0 0 0-1.04-1.56 1.7 1.7 0 0 0-1.87.34l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.7 1.7 0 0 0 .34-1.87 1.7 1.7 0 0 0-1.56-1.04H3a2 2 0 1 1 0-4h.09a1.7 1.7 0 0 0 1.56-1.04 1.7 1.7 0 0 0-.34-1.87l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.7 1.7 0 0 0 1.87.34H9a1.7 1.7 0 0 0 1.04-1.56V3a2 2 0 1 1 4 0v.09a1.7 1.7 0 0 0 1.04 1.56 1.7 1.7 0 0 0 1.87-.34l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.7 1.7 0 0 0-.34 1.87V9a1.7 1.7 0 0 0 1.56 1.04H21a2 2 0 1 1 0 4h-.09a1.7 1.7 0 0 0-1.56 1.04Z" /></Svg>;
}
export function IconLock(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" /></Svg>;
}
export function IconEye(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7-10-7-10-7Z" /><circle cx="12" cy="12" r="3" /></Svg>;
}
export function IconEyeOff(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M3 3l18 18" /><path d="M10.6 5.2A10.6 10.6 0 0 1 12 5c6.4 0 10 7 10 7a17.3 17.3 0 0 1-3.4 4.3M6.6 6.6C4 8.3 2 12 2 12s3.6 7 10 7c1.3 0 2.5-.2 3.6-.6" /><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2" /></Svg>;
}
export function IconRefresh(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M21 12a9 9 0 1 1-3-6.7" /><path d="M21 3v5h-5" /></Svg>;
}
export function IconCheck(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M20 6 9 17l-5-5" /></Svg>;
}
export function IconWarning(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M12 3 1 21h22Z" /><path d="M12 9.5v5" /><path d="M12 17.5h.01" /></Svg>;
}
export function IconFolder(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M3 6.5A1.5 1.5 0 0 1 4.5 5h4l2 2.5h9A1.5 1.5 0 0 1 21 9v8.5A1.5 1.5 0 0 1 19.5 19h-15A1.5 1.5 0 0 1 3 17.5Z" /></Svg>;
}
export function IconTag(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M20 13 12.5 20.5a2.1 2.1 0 0 1-3 0L3.5 14.5a2.1 2.1 0 0 1 0-3L11 4h7a2 2 0 0 1 2 2Z" /><circle cx="15.5" cy="8.5" r="1" /></Svg>;
}
export function IconTrash(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><path d="M3 6h18" /><path d="M8 6V4h8v2" /><path d="M19 6l-1 15H6L5 6" /><path d="M10 11v5M14 11v5" /></Svg>;
}
export function IconUser(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><circle cx="12" cy="8" r="4" /><path d="M4 20c1.5-4 5-6 8-6s6.5 2 8 6" /></Svg>;
}
export function IconUsers(props: SVGProps<SVGSVGElement>) {
    return <Svg {...props}><circle cx="9" cy="8" r="3.2" /><path d="M2.5 19.5c1.2-3.4 4-5 6.5-5s5.3 1.6 6.5 5" /><path d="M16.2 5.2a3.2 3.2 0 0 1 0 6" /><path d="M17.5 14.7c2.1.5 3.7 2.2 4.5 4.8" /></Svg>;
}
