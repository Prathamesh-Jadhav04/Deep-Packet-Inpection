'use client';

import React from 'react';

export type SpotlightVariant = 'violet' | 'magenta' | 'orange' | 'coral';

export function GradientSpotlightCard({
  variant = 'violet',
  title,
  description,
  children,
}: {
  variant?: SpotlightVariant;
  title?: string;
  description?: string;
  children?: React.ReactNode;
}) {
  const variantClass =
    variant === 'violet'
      ? 'dpi-spotlight-violet'
      : variant === 'magenta'
        ? 'dpi-spotlight-magenta'
        : variant === 'orange'
          ? 'dpi-spotlight-orange'
          : 'dpi-spotlight-coral';

  return (
    <section className={`dpi-spotlight ${variantClass}`}>
      {title && <h3 className="text-display-sm text-[var(--text)]">{title}</h3>}
      {description && <p className="mt-2 text-body-md text-[var(--text-secondary)]">{description}</p>}
      {children}
    </section>
  );
}
