import type { Metadata } from "next";
import "./globals.css";
import { Sidebar } from "@/components/layout/Sidebar";
import { TopHeader } from "@/components/layout/TopHeader";

export const metadata: Metadata = {
  title: "EndpointGuard | 100% Agentless Endpoint Audit & Compliance",
  description:
    "Open-source, 100% agentless endpoint audit, hardware inventory, and CIS compliance platform for Windows 11 and Windows Server via WinRM/CIM over HTTPS.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="bg-charcoal-50 text-charcoal-950 min-h-screen flex antialiased">
        {/* Persistent Enterprise Sidebar */}
        <Sidebar />

        {/* Main Content Area */}
        <div className="flex-1 flex flex-col min-w-0 overflow-x-hidden">
          <TopHeader />
          <main className="flex-1 p-6 md:p-8 max-w-7xl w-full mx-auto">{children}</main>
        </div>
      </body>
    </html>
  );
}
