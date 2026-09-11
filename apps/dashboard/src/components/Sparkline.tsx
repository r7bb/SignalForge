"use client";

interface Props {
  values: number[];
  width?: number;
  height?: number;
  /** Series colour for the line; the end dot uses the same hue. */
  color?: string;
  label?: string;
}

/**
 * 12-point trend line: 2px stroke, round caps, an >=8px end marker with a 2px
 * surface ring so it stays legible where it crosses the line. Single series,
 * so no legend - the tile's label says what is plotted.
 */
export function Sparkline({
  values,
  width = 120,
  height = 28,
  color = "var(--series-1)",
  label,
}: Props) {
  if (values.length < 2) return null;

  const padding = 3;
  const max = Math.max(...values);
  const min = Math.min(...values);
  const span = max - min || 1;
  const stepX = (width - padding * 2) / (values.length - 1);

  const points = values.map((value, index) => {
    const x = padding + index * stepX;
    const y = height - padding - ((value - min) / span) * (height - padding * 2);
    return [x, y] as const;
  });

  const path = points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
  const [lastX, lastY] = points[points.length - 1];

  return (
    <svg
      className="chart-svg"
      viewBox={`0 0 ${width} ${height}`}
      width={width}
      height={height}
      role="img"
      aria-label={label ?? `Trend of ${values.length} points, latest ${values[values.length - 1]}`}
    >
      <polyline
        points={path}
        fill="none"
        stroke={color}
        strokeWidth={2}
        strokeLinejoin="round"
        strokeLinecap="round"
      />
      <circle cx={lastX} cy={lastY} r={4} fill={color} stroke="var(--surface-1)" strokeWidth={2} />
    </svg>
  );
}
