'use client';

import { useEffect, useState } from 'react';
import { motion, useMotionValue, useSpring } from 'framer-motion';

export function CustomCursor() {
  const [visible, setVisible] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [isMobile, setIsMobile] = useState(false);

  // Exact coordinates of the mouse
  const cursorX = useMotionValue(-100);
  const cursorY = useMotionValue(-100);

  // Spring physics for trailing effect
  const springConfig = { damping: 35, stiffness: 350, mass: 0.35 };
  const ringX = useSpring(cursorX, springConfig);
  const ringY = useSpring(cursorY, springConfig);

  useEffect(() => {
    // Check if the device is mobile or touch-enabled
    const checkTouch = () => {
      const mobile =
        window.matchMedia('(max-width: 768px)').matches ||
        'ontouchstart' in window ||
        navigator.maxTouchPoints > 0;
      setIsMobile(mobile);
      if (!mobile) {
        document.body.classList.add('custom-cursor-active');
      }
    };

    checkTouch();

    const moveCursor = (e: MouseEvent) => {
      cursorX.set(e.clientX);
      cursorY.set(e.clientY);
      if (!visible) setVisible(true);
    };

    const handleMouseLeave = () => setVisible(false);
    const handleMouseEnter = () => setVisible(true);

    window.addEventListener('mousemove', moveCursor);
    document.addEventListener('mouseleave', handleMouseLeave);
    document.addEventListener('mouseenter', handleMouseEnter);

    // Detect if hover target is clickable to scale cursor
    const handleMouseOver = (e: MouseEvent) => {
      const target = e.target as HTMLElement;
      if (!target) return;

      const isClickable =
        target.tagName === 'A' ||
        target.tagName === 'BUTTON' ||
        target.tagName === 'INPUT' ||
        target.tagName === 'SELECT' ||
        target.tagName === 'TEXTAREA' ||
        target.closest('a') ||
        target.closest('button') ||
        target.closest('[role="tab"]') ||
        target.closest('[role="button"]') ||
        target.style.cursor === 'pointer';

      setHovered(!!isClickable);
    };

    document.addEventListener('mouseover', handleMouseOver);

    return () => {
      window.removeEventListener('mousemove', moveCursor);
      document.removeEventListener('mouseleave', handleMouseLeave);
      document.removeEventListener('mouseenter', handleMouseEnter);
      document.removeEventListener('mouseover', handleMouseOver);
      document.body.classList.remove('custom-cursor-active');
    };
  }, [cursorX, cursorY, visible]);

  if (isMobile || !visible) return null;

  return (
    <>
      {/* Inner Dot following cursor precisely */}
      <motion.div
        className="fixed top-0 left-0 w-1.5 h-1.5 rounded-full pointer-events-none z-[9999] mix-blend-difference bg-white"
        style={{
          x: cursorX,
          y: cursorY,
          translateX: '-50%',
          translateY: '-50%',
        }}
      />
      {/* Outer Ring lagging slightly with spring motion */}
      <motion.div
        className="fixed top-0 left-0 rounded-full pointer-events-none z-[9998] border border-[var(--border-strong)]"
        style={{
          x: ringX,
          y: ringY,
          translateX: '-50%',
          translateY: '-50%',
          width: hovered ? 38 : 20,
          height: hovered ? 38 : 20,
          backgroundColor: hovered ? 'var(--accent-blue-soft)' : 'transparent',
          borderColor: hovered ? 'var(--accent-blue)' : 'var(--border-strong)',
        }}
        animate={{
          scale: hovered ? 1.15 : 1,
        }}
        transition={{ type: 'spring', stiffness: 450, damping: 20 }}
      />
    </>
  );
}
