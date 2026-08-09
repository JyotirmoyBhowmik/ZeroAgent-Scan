import Link from "next/link";
import { AlertCircle, ArrowLeft } from "lucide-react";

export default function NotFound() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[500px] text-center p-6 space-y-4">
      <div className="w-12 h-12 rounded-xl bg-charcoal-100 border border-charcoal-300 text-charcoal-700 flex items-center justify-center">
        <AlertCircle className="w-6 h-6 text-red-500" />
      </div>
      <h1 className="text-xl font-bold text-charcoal-950">Resource Not Found</h1>
      <p className="text-xs text-charcoal-500 max-w-sm">
        The requested endpoint or configuration does not exist or has been retired from the active fleet.
      </p>
      <Link
        href="/"
        className="inline-flex items-center gap-2 px-4 py-2 bg-charcoal-950 hover:bg-charcoal-800 text-white text-xs font-semibold rounded-lg transition-colors shadow-sm"
      >
        <ArrowLeft className="w-3.5 h-3.5" />
        <span>Return to Dashboard</span>
      </Link>
    </div>
  );
}
