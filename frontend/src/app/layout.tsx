import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Cyber-LLM - Security Foundation Model',
  description: 'Domain-specific AI for offensive and defensive cybersecurity',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="min-h-screen">{children}</body>
    </html>
  )
}
