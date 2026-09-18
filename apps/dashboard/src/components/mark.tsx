/** The wireframe V. Decorative beside the wordmark, so it is hidden from AT. */
export function Mark({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.1"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d="M3 4h5l4 13 4-13h5l-6.5 16h-5L3 4z" />
      <path d="M8 4l4 13 4-13" opacity="0.4" />
    </svg>
  );
}
