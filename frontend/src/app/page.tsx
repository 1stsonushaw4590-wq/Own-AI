'use client'

import { useState, useRef, useEffect } from 'react'
import ReactMarkdown from 'react-markdown'

type Message = {
  role: 'user' | 'assistant'
  content: string
}

const DOMAINS = [
  'Offensive Security', 'Defensive Security', 'Secure Coding', 'App Security',
  'Cloud Security', 'Network Security', 'Malware Analysis', 'Reverse Engineering',
  'Digital Forensics', 'Incident Response', 'Threat Hunting', 'Detection Engineering',
  'Threat Intelligence', 'Governance', 'Risk Management', 'Compliance',
  'DevSecOps', 'AI Security', 'K8s Security', 'IAM',
]

export default function Home() {
  const [messages, setMessages] = useState<Message[]>([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [mode, setMode] = useState<'chat' | 'review' | 'analyze'>('chat')
  const [codeInput, setCodeInput] = useState('')
  const chatEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const sendMessage = async () => {
    if (!input.trim() || loading) return
    const userMsg: Message = { role: 'user', content: input }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const res = await fetch('/api/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: 'cyber-llm',
          messages: [...messages, userMsg].map(m => ({ role: m.role, content: m.content })),
          temperature: 0.6,
          max_tokens: 2048,
          use_rag: true,
        }),
      })
      const data = await res.json()
      const content = data.choices?.[0]?.message?.content || 'No response'
      setMessages(prev => [...prev, { role: 'assistant', content }])
    } catch (err) {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: 'Error connecting to API. Make sure the backend is running.',
      }])
    } finally {
      setLoading(false)
    }
  }

  const submitCodeReview = async () => {
    if (!codeInput.trim()) return
    setLoading(true)
    try {
      const res = await fetch('/api/code/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: codeInput, language: 'python' }),
      })
      const data = await res.json()
      setMessages([{ role: 'assistant', content: data.explanation }])
    } catch {
      setMessages([{ role: 'assistant', content: 'Error running code review.' }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <aside className="w-64 bg-surface border-r border-border p-4 flex flex-col">
        <div className="flex items-center gap-2 mb-6">
          <div className="w-3 h-3 rounded-full bg-cyber-500" />
          <h1 className="text-lg font-bold text-white">Cyber-LLM</h1>
        </div>

        <div className="flex gap-1 mb-4">
          {(['chat', 'review'] as const).map(m => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-3 py-1 rounded text-sm capitalize ${
                mode === m ? 'bg-cyber-700 text-white' : 'text-gray-400 hover:text-white'
              }`}
            >
              {m}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto">
          <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Domains</p>
          <div className="flex flex-wrap gap-1">
            {DOMAINS.map(d => (
              <button
                key={d}
                onClick={() => setInput(`Explain ${d} best practices`)}
                className="text-xs px-2 py-1 bg-surface-2 rounded text-gray-400 hover:text-cyber-400"
              >
                {d}
              </button>
            ))}
          </div>
        </div>

        <div className="mt-4 pt-4 border-t border-border text-xs text-gray-500">
          Model: Qwen2.5-Coder-7B-Cyber
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 flex flex-col">
        {mode === 'chat' ? (
          <>
            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.length === 0 && (
                <div className="text-center mt-20">
                  <div className="w-16 h-16 rounded-full bg-cyber-900/50 mx-auto mb-4
                    flex items-center justify-center">
                    <span className="text-3xl">🛡️</span>
                  </div>
                  <h2 className="text-xl text-white mb-2">Cyber Security Assistant</h2>
                  <p className="text-gray-500 max-w-md mx-auto">
                    Ask about vulnerabilities, secure coding, threat intelligence,
                    or any cybersecurity topic. Your code runs in an isolated sandbox.
                  </p>
                </div>
              )}

              {messages.map((msg, i) => (
                <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
                  <div className={`max-w-[80%] rounded-xl p-4 ${
                    msg.role === 'user'
                      ? 'bg-cyber-700 text-white'
                      : 'bg-surface-2 text-gray-200'
                  }`}>
                    <ReactMarkdown className="prose prose-invert prose-sm max-w-none
                      prose-code:bg-surface prose-code:px-1 prose-code:rounded">
                      {msg.content}
                    </ReactMarkdown>
                  </div>
                </div>
              ))}

              {loading && (
                <div className="flex justify-start">
                  <div className="bg-surface-2 rounded-xl p-4">
                    <div className="flex gap-1">
                      <div className="w-2 h-2 bg-cyber-500 rounded-full animate-bounce" />
                      <div className="w-2 h-2 bg-cyber-500 rounded-full animate-bounce [animation-delay:0.1s]" />
                      <div className="w-2 h-2 bg-cyber-500 rounded-full animate-bounce [animation-delay:0.2s]" />
                    </div>
                  </div>
                </div>
              )}
              <div ref={chatEndRef} />
            </div>

            {/* Input */}
            <div className="border-t border-border p-4">
              <div className="flex gap-2">
                <input
                  value={input}
                  onChange={e => setInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && sendMessage()}
                  placeholder="Ask a cybersecurity question..."
                  className="input-field"
                  disabled={loading}
                />
                <button onClick={sendMessage} disabled={loading} className="btn-primary">
                  Send
                </button>
              </div>
            </div>
          </>
        ) : (
          /* Code Review mode */
          <div className="flex-1 p-4 flex gap-4">
            <div className="flex-1 flex flex-col">
              <textarea
                value={codeInput}
                onChange={e => setCodeInput(e.target.value)}
                placeholder="Paste code for security review..."
                className="input-field flex-1 font-mono text-sm"
                style={{ minHeight: '300px' }}
              />
              <button onClick={submitCodeReview} disabled={loading} className="btn-primary mt-2 self-end">
                Review Code
              </button>
            </div>
            <div className="flex-1 overflow-y-auto">
              {messages.map((msg, i) => (
                <div key={i} className="card">
                  <ReactMarkdown className="prose prose-invert prose-sm">
                    {msg.content}
                  </ReactMarkdown>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  )
}
