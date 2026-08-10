"use client";

import React, { useState, useRef, useEffect, useId } from "react";
import { Info, HelpCircle, X } from "lucide-react";
import { getGlossaryEntry, GlossaryKey, GlossaryEntry } from "@/lib/glossary";

export interface InfoTooltipProps {
  fieldId?: GlossaryKey | string;
  title?: string;
  description?: string;
  format?: string;
  example?: string;
  className?: string;
  iconClassName?: string;
  position?: "top" | "bottom" | "left" | "right";
}

export function InfoTooltip({
  fieldId,
  title,
  description,
  format,
  example,
  className = "",
  iconClassName = "",
  position = "top",
}: InfoTooltipProps) {
  const [isOpen, setIsOpen] = useState(false);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const timeoutRef = useRef<NodeJS.Timeout | null>(null);
  const tooltipId = useId();

  // Resolve content from glossary if fieldId provided
  let entry: GlossaryEntry | null = null;
  if (fieldId) {
    entry = getGlossaryEntry(fieldId);
  }

  const resolvedTitle = title || entry?.title || "Field Information";
  const resolvedDesc = description || entry?.description || "";
  const resolvedFormat = format || entry?.format || "";
  const resolvedExample = example || entry?.example || "";

  const handleMouseEnter = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(() => setIsOpen(true), 150);
  };

  const handleMouseLeave = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    timeoutRef.current = setTimeout(() => setIsOpen(false), 200);
  };

  const handleToggle = (e: React.MouseEvent) => {
    e.stopPropagation();
    setIsOpen((prev) => !prev);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape" && isOpen) {
      setIsOpen(false);
      triggerRef.current?.focus();
    }
  };

  // Close on outside click
  useEffect(() => {
    if (!isOpen) return;

    function handleClickOutside(event: MouseEvent) {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(event.target as Node) &&
        triggerRef.current &&
        !triggerRef.current.contains(event.target as Node)
      ) {
        setIsOpen(false);
      }
    }

    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isOpen]);

  // Position classes
  const getPositionClasses = () => {
    switch (position) {
      case "bottom":
        return "top-full mt-2 left-1/2 -translate-x-1/2";
      case "left":
        return "right-full mr-2 top-1/2 -translate-y-1/2";
      case "right":
        return "left-full ml-2 top-1/2 -translate-y-1/2";
      case "top":
      default:
        return "bottom-full mb-2 left-1/2 -translate-x-1/2";
    }
  };

  return (
    <span
      className={`relative inline-flex items-center align-middle ${className}`}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <button
        ref={triggerRef}
        type="button"
        onClick={handleToggle}
        onFocus={() => setIsOpen(true)}
        onBlur={() => handleMouseLeave()}
        onKeyDown={handleKeyDown}
        aria-describedby={isOpen ? tooltipId : undefined}
        aria-expanded={isOpen}
        aria-label={`Contextual help for ${resolvedTitle}`}
        className={`w-4 h-4 rounded-full inline-flex items-center justify-center text-charcoal-400 hover:text-charcoal-800 hover:bg-charcoal-100 focus:outline-none focus:ring-2 focus:ring-charcoal-900 focus:text-charcoal-950 transition-colors cursor-help shrink-0 ${iconClassName}`}
      >
        <Info className="w-3.5 h-3.5" />
      </button>

      {isOpen && (
        <div
          ref={popoverRef}
          id={tooltipId}
          role="tooltip"
          onMouseEnter={() => {
            if (timeoutRef.current) clearTimeout(timeoutRef.current);
          }}
          onMouseLeave={handleMouseLeave}
          className={`absolute ${getPositionClasses()} z-50 w-72 p-3.5 bg-charcoal-950 text-white rounded-xl shadow-2xl border border-charcoal-800 text-left font-sans text-xs leading-relaxed animate-in fade-in zoom-in-95 duration-150 pointer-events-auto`}
        >
          {/* Header */}
          <div className="flex items-center justify-between border-b border-charcoal-800 pb-2 mb-2">
            <div className="flex items-center gap-1.5 font-bold text-xs text-white">
              <HelpCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>{resolvedTitle}</span>
            </div>
            <button
              type="button"
              onClick={() => setIsOpen(false)}
              aria-label="Close tooltip"
              className="text-charcoal-400 hover:text-white transition-colors"
            >
              <X className="w-3 h-3" />
            </button>
          </div>

          {/* Description */}
          {resolvedDesc && (
            <p className="text-[11px] text-charcoal-300 mb-2.5 leading-normal">
              {resolvedDesc}
            </p>
          )}

          {/* Format & Example Boxes */}
          <div className="space-y-1.5 text-[10px] font-mono">
            {resolvedFormat && (
              <div className="p-1.5 rounded bg-charcoal-900 border border-charcoal-800 flex items-start gap-1.5">
                <span className="text-charcoal-500 font-bold uppercase tracking-wider select-none shrink-0">
                  Format:
                </span>
                <span className="text-amber-300 font-medium break-all">
                  {resolvedFormat}
                </span>
              </div>
            )}

            {resolvedExample && (
              <div className="p-1.5 rounded bg-charcoal-900 border border-charcoal-800 flex items-start gap-1.5">
                <span className="text-charcoal-500 font-bold uppercase tracking-wider select-none shrink-0">
                  Example:
                </span>
                <span className="text-emerald-300 font-medium break-all">
                  {resolvedExample}
                </span>
              </div>
            )}
          </div>
        </div>
      )}
    </span>
  );
}
