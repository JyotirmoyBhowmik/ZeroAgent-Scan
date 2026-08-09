import React from "react";
import { LucideIcon } from "lucide-react";

interface StatCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  change?: string;
  changeType?: "positive" | "negative" | "neutral";
  icon: LucideIcon;
  accentColor?: "emerald" | "indigo" | "amber" | "crimson" | "charcoal";
}

export function StatCard({
  title,
  value,
  subtitle,
  change,
  changeType = "positive",
  icon: Icon,
  accentColor = "charcoal",
}: StatCardProps) {
  const getBadgeStyle = () => {
    switch (changeType) {
      case "positive":
        return "bg-emerald-50 text-emerald-700 border-emerald-200";
      case "negative":
        return "bg-red-50 text-red-700 border-red-200";
      default:
        return "bg-charcoal-100 text-charcoal-700 border-charcoal-200";
    }
  };

  const getIconStyle = () => {
    switch (accentColor) {
      case "emerald":
        return "bg-emerald-50 text-emerald-600 border-emerald-200";
      case "indigo":
        return "bg-indigo-50 text-indigo-600 border-indigo-200";
      case "amber":
        return "bg-amber-50 text-amber-600 border-amber-200";
      case "crimson":
        return "bg-red-50 text-red-600 border-red-200";
      default:
        return "bg-charcoal-100 text-charcoal-900 border-charcoal-200";
    }
  };

  return (
    <div className="bg-white p-5 rounded-xl border border-charcoal-200 card-border-hover transition-all">
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-charcoal-500">{title}</span>
        <div className={`p-2 rounded-lg border ${getIconStyle()}`}>
          <Icon className="w-4 h-4" />
        </div>
      </div>

      <div className="mt-3 flex items-baseline gap-2">
        <span className="text-2xl font-bold tracking-tight text-charcoal-950">{value}</span>
        {change && (
          <span className={`text-[11px] font-semibold px-1.5 py-0.5 rounded border ${getBadgeStyle()}`}>
            {change}
          </span>
        )}
      </div>

      {subtitle && <p className="mt-1 text-xs text-charcoal-500">{subtitle}</p>}
    </div>
  );
}
