import React from "react";

interface BadgeProps {
  children: React.ReactNode;
  variant?: "success" | "warning" | "danger" | "neutral" | "info";
  size?: "sm" | "md";
}

export function Badge({ children, variant = "neutral", size = "sm" }: BadgeProps) {
  const styles = {
    success: "bg-emerald-50 text-emerald-700 border-emerald-200",
    warning: "bg-amber-50 text-amber-700 border-amber-200",
    danger: "bg-red-50 text-red-700 border-red-200",
    neutral: "bg-charcoal-100 text-charcoal-700 border-charcoal-200",
    info: "bg-indigo-50 text-indigo-700 border-indigo-200",
  };

  const sizes = {
    sm: "px-2 py-0.5 text-[11px]",
    md: "px-2.5 py-1 text-xs",
  };

  return (
    <span className={`inline-flex items-center font-medium rounded border ${styles[variant]} ${sizes[size]}`}>
      {children}
    </span>
  );
}
