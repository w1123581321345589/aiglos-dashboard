import { useState, useEffect, useRef, useCallback } from "react";

// ─── MOCK DATA ENGINE ────────────────────────────────────────────────────────

const TOOL_NAMES = ["read_file","write_file","bash","http_request","search_files",
  "git_commit","edit_file","list_directory","run_tests","fetch_url"];
const MODELS = ["claude-sonnet-4-6","claude-opus-4-6","gpt-4o","gemini-1.5-pro"];
const GOALS = [
  "Refactor authentication module to use OAuth2",
  "Deploy staging environment and run smoke tests",
  "Analyze Q3 financial reports and generate summary",
  "Update CMMC documentation and evidence packages",
  "Review and merge open pull requests",
  "Optimize PostgreSQL query performance",
  "Generate weekly security posture report",
];
const INITIATORS = ["will@clawdguard.io","ci-pipeline","cursor-agent","copilot-workspace","analyst-01"];

const EVENT_TEMPLATES = [
  { type:"credential_detected", sev:"critical", title:"Credential detected: AWS Access Key", cmmc:["3.13.10","3.13.16"] },
  { type:"goal_drift", sev:"high", title:"Goal drift detected (score: 0.21)", cmmc:["3.13.3","3.14.7"] },
  { type:"command_injection", sev:"critical", title:"Command injection pattern detected", cmmc:["3.14.2","3.14.6"] },
  { type:"policy_violation", sev:"high", title:"Policy violation: block_sudo", cmmc:["3.1.1","3.1.2"] },
  { type:"path_traversal", sev:"high", title:"Path traversal pattern detected", cmmc:["3.1.3","3.14.2"] },
  { type:"tool_call", sev:"info", title:"Tool call intercepted: read_file", cmmc:["3.3.1"] },
  { type:"agent_attested", sev:"info", title:"Session attestation produced", cmmc:["3.3.2","3.5.2"] },
  { type:"policy_violation", sev:"medium", title:"Policy match: alert_shell_execution", cmmc:["3.3.1","3.4.1"] },
  { type:"credential_detected", sev:"high", title:"High-entropy string detected in arguments", cmmc:["3.13.10"] },
  { type:"goal_drift", sev:"medium", title:"Goal alignment degraded (score: 0.54)", cmmc:["3.1.1"] },
];

const SEV_ORDER = { critical:0, high:1, medium:2, low:3, info:4 };

let _id = 1000;
const uid = () => (++_id).toString(36) + Math.random().toString(36).slice(2,6);

function makeSession() {
  const id = uid();
  return {
    id,
    model: MODELS[Math.floor(Math.random()*MODELS.length)],
    goal: GOALS[Math.floor(Math.random()*GOALS.length)],
    initiator: INITIATORS[Math.floor(Math.random()*INITIATORS.length)],
    startTime: Date.now() - Math.floor(Math.random()*3600000),
    endTime: Math.random() > 0.3 ? Date.now() - Math.floor(Math.random()*600000) : null,
    isActive: Math.random() > 0.5,
    goalIntegrity: 0.5 + Math.random()*0.5,
    anomalyScore: Math.random()*0.4,
    toolCalls: Math.floor(Math.random()*80)+5,
    blockedCalls: Math.floor(Math.random()*6),
    attestationHash: Array.from({length:16}, ()=>"0123456789abcdef"[Math.floor(Math.random()*16)]).join(""),
  };
}

function makeEvent(sessionId) {
  const tpl = EVENT_TEMPLATES[Math.floor(Math.random()*EVENT_TEMPLATES.length)];
  return {
    id: uid(),
    sessionId: sessionId || uid(),
    ...tpl,
    description: `Agent session ${sessionId ? sessionId.slice(0,8) : uid().slice(0,8)} — ${tpl.title.toLowerCase()}`,
    timestamp: Date.now() - Math.floor(Math.random()*30000),
    details: { tool: TOOL_NAMES[Math.floor(Math.random()*TOOL_NAMES.length)] },
  };
}

// ─── STYLE CONSTANTS ─────────────────────────────────────────────────────────

const SEV_COLORS = {
  critical: { bg:"#3D0A0A", border:"#FF2D2D", text:"#FF6B6B", dot:"#FF2D2D", badge:"rgba(255,45,45,0.15)" },
  high:     { bg:"#2D1A00", border:"#FF7A00", text:"#FFA040", dot:"#FF7A00", badge:"rgba(255,122,0,0.15)" },
  medium:   { bg:"#2D2800", border:"#F0C000", text:"#F0C000", dot:"#F0C000", badge:"rgba(240,192,0,0.12)" },
  low:      { bg:"#001D2D", border:"#00B4E6", text:"#40CCFF", dot:"#00B4E6", badge:"rgba(0,180,230,0.12)" },
  info:     { bg:"#111418", border:"#3A4550", text:"#6B7A88", dot:"#3A4550", badge:"rgba(58,69,80,0.3)" },
};

const css = `
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@300;400;500;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg0: #080B0E;
    --bg1: #0C1014;
    --bg2: #111418;
    --bg3: #161C22;
    --bg4: #1C242C;
    --border: rgba(255,255,255,0.06);
    --border-bright: rgba(255,255,255,0.12);
    --text-primary: #E8EDF2;
    --text-secondary: #8A9BAA;
    --text-dim: #4A5A68;
    --amber: #F0A000;
    --amber-dim: rgba(240,160,0,0.15);
    --green: #00C878;
    --green-dim: rgba(0,200,120,0.12);
    --red: #FF2D2D;
    --red-dim: rgba(255,45,45,0.12);
    --mono: 'IBM Plex Mono', monospace;
    --sans: 'IBM Plex Sans', sans-serif;
    --radius: 6px;
  }

  body { background: var(--bg0); color: var(--text-primary); font-family: var(--sans); overflow: hidden; height: 100vh; }

  ::-webkit-scrollbar { width: 4px; height: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--bg4); border-radius: 2px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--border-bright); }

  @keyframes pulse-dot {
    0%,100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.7); }
  }
  @keyframes slide-in {
    from { opacity: 0; transform: translateY(-8px); }
    to { opacity: 1; transform: translateY(0); }
  }
  @keyframes fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
  @keyframes scan-line {
    0% { transform: translateY(-100%); }
    100% { transform: translateY(800%); }
  }
  @keyframes glow-pulse {
    0%,100% { box-shadow: 0 0 8px rgba(240,160,0,0.3); }
    50% { box-shadow: 0 0 20px rgba(240,160,0,0.6); }
  }
`;

// ─── COMPONENTS ──────────────────────────────────────────────────────────────

function SevDot({ sev, animate }) {
  const c = SEV_COLORS[sev] || SEV_COLORS.info;
  return (
    <span style={{
      display:"inline-block", width:7, height:7, borderRadius:"50%",
      background: c.dot, flexShrink:0,
      animation: animate && (sev==="critical"||sev==="high") ? "pulse-dot 1.4s ease-in-out infinite" : "none",
      boxShadow: (sev==="critical"||sev==="high") ? `0 0 6px ${c.dot}` : "none",
    }} />
  );
}

function SevBadge({ sev }) {
  const c = SEV_COLORS[sev] || SEV_COLORS.info;
  return (
    <span style={{
      fontFamily:"var(--mono)", fontSize:9, fontWeight:600, letterSpacing:"0.08em",
      color: c.text, background: c.badge, border:`1px solid ${c.border}33`,
      padding:"1px 6px", borderRadius:3, textTransform:"uppercase",
    }}>
      {sev}
    </span>
  );
}

function StatCard({ label, value, sub, accent, icon }) {
  const color = accent === "red" ? "var(--red)" : accent === "green" ? "var(--green)" : accent === "amber" ? "var(--amber)" : "var(--text-primary)";
  return (
    <div style={{
      background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--radius)",
      padding:"14px 16px", position:"relative", overflow:"hidden",
    }}>
      <div style={{
        position:"absolute", top:0, left:0, right:0, height:1,
        background: accent === "red" ? "linear-gradient(90deg,transparent,var(--red),transparent)"
          : accent === "amber" ? "linear-gradient(90deg,transparent,var(--amber),transparent)"
          : "linear-gradient(90deg,transparent,var(--border-bright),transparent)",
      }} />
      <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)", letterSpacing:"0.1em", textTransform:"uppercase", marginBottom:8 }}>
        {icon && <span style={{marginRight:5}}>{icon}</span>}{label}
      </div>
      <div style={{ fontFamily:"var(--mono)", fontSize:26, fontWeight:600, color, lineHeight:1 }}>
        {value}
      </div>
      {sub && <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)", marginTop:5 }}>{sub}</div>}
    </div>
  );
}

function IntegrityBar({ score }) {
  const pct = Math.round(score * 100);
  const color = score > 0.7 ? "var(--green)" : score > 0.35 ? "var(--amber)" : "var(--red)";
  return (
    <div style={{ display:"flex", alignItems:"center", gap:8, width:"100%" }}>
      <div style={{ flex:1, height:4, background:"var(--bg4)", borderRadius:2, overflow:"hidden" }}>
        <div style={{ width:`${pct}%`, height:"100%", background:color, borderRadius:2,
          transition:"width 0.6s ease", boxShadow:`0 0 4px ${color}80` }} />
      </div>
      <span style={{ fontFamily:"var(--mono)", fontSize:10, color, width:34, textAlign:"right" }}>
        {pct}%
      </span>
    </div>
  );
}

function LiveDot() {
  return (
    <span style={{ display:"inline-flex", alignItems:"center", gap:5, fontFamily:"var(--mono)",
      fontSize:9, color:"var(--green)", textTransform:"uppercase", letterSpacing:"0.1em" }}>
      <span style={{ width:5, height:5, borderRadius:"50%", background:"var(--green)",
        animation:"pulse-dot 1.2s ease-in-out infinite", boxShadow:"0 0 6px var(--green)" }} />
      LIVE
    </span>
  );
}

function formatTime(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-US", { hour12:false, hour:"2-digit", minute:"2-digit", second:"2-digit" });
}

function formatDuration(ms) {
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s%60}s`;
  return `${Math.floor(m/60)}h ${m%60}m`;
}

// ─── MAIN DASHBOARD ──────────────────────────────────────────────────────────

export default function ClawdGuardDashboard() {
  const [sessions, setSessions] = useState(() => Array.from({length:8}, makeSession));
  const [events, setEvents] = useState(() => {
    const s = Array.from({length:8}, makeSession);
    return Array.from({length:24}, () => makeEvent(s[Math.floor(Math.random()*s.length)].id))
      .sort((a,b) => b.timestamp - a.timestamp);
  });
  const [selectedSession, setSelectedSession] = useState(null);
  const [activeTab, setActiveTab] = useState("overview");
  const [tick, setTick] = useState(0);
  const [newEventIds, setNewEventIds] = useState(new Set());
  const eventListRef = useRef(null);

  // Simulate live data
  useEffect(() => {
    const interval = setInterval(() => {
      setTick(t => t + 1);

      // Occasionally add a new event
      if (Math.random() < 0.45) {
        const targetSession = sessions[Math.floor(Math.random() * sessions.length)];
        const newEv = { ...makeEvent(targetSession.id), timestamp: Date.now() };
        const newId = newEv.id;
        setEvents(prev => [newEv, ...prev.slice(0, 199)]);
        setNewEventIds(prev => new Set([...prev, newId]));
        setTimeout(() => setNewEventIds(prev => { const n = new Set(prev); n.delete(newId); return n; }), 1200);
      }

      // Occasionally update a session's scores
      if (Math.random() < 0.3) {
        setSessions(prev => prev.map(s => {
          if (s.isActive && Math.random() < 0.4) {
            const drift = (Math.random()-0.5)*0.08;
            return { ...s, goalIntegrity: Math.max(0.05, Math.min(1, s.goalIntegrity+drift)),
              toolCalls: s.toolCalls + (Math.random()<0.6 ? 1 : 0) };
          }
          return s;
        }));
      }

      // Occasionally add a new active session
      if (Math.random() < 0.04) {
        setSessions(prev => [{ ...makeSession(), isActive:true }, ...prev.slice(0, 14)]);
      }
    }, 1800);
    return () => clearInterval(interval);
  }, [sessions]);

  const totalToolCalls = sessions.reduce((s,x) => s+x.toolCalls, 0);
  const totalBlocked = sessions.reduce((s,x) => s+x.blockedCalls, 0);
  const activeSessions = sessions.filter(s => s.isActive).length;
  const criticalEvents = events.filter(e => e.sev === "critical").length;
  const highEvents = events.filter(e => e.sev === "high").length;
  const avgIntegrity = sessions.filter(s=>s.isActive).reduce((s,x)=>s+x.goalIntegrity,0) / Math.max(activeSessions,1);

  const selectedSessionData = sessions.find(s => s.id === selectedSession);
  const sessionEvents = selectedSession ? events.filter(e => e.sessionId === selectedSession) : [];

  return (
    <>
      <style>{css}</style>
      <div style={{ height:"100vh", display:"flex", flexDirection:"column", background:"var(--bg0)", userSelect:"none" }}>

        {/* ── TOPBAR ── */}
        <div style={{
          height:48, background:"var(--bg1)", borderBottom:"1px solid var(--border)",
          display:"flex", alignItems:"center", padding:"0 20px", gap:24, flexShrink:0,
          position:"relative",
        }}>
          {/* Scan line effect */}
          <div style={{
            position:"absolute", top:0, left:0, right:0, height:1,
            background:"linear-gradient(90deg,transparent,var(--amber)33,transparent)",
            pointerEvents:"none",
          }} />

          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <div style={{
              width:28, height:28, borderRadius:6, background:"var(--amber-dim)",
              border:"1px solid var(--amber)44", display:"flex", alignItems:"center", justifyContent:"center",
              animation:"glow-pulse 3s ease-in-out infinite",
            }}>
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none">
                <path d="M8 1L10 6H15L11 9.5L12.5 15L8 12L3.5 15L5 9.5L1 6H6L8 1Z"
                  fill="var(--amber)" />
              </svg>
            </div>
            <div>
              <div style={{ fontFamily:"var(--mono)", fontSize:13, fontWeight:600, letterSpacing:"0.05em", color:"var(--text-primary)" }}>
                CLAWDGUARD
              </div>
              <div style={{ fontFamily:"var(--mono)", fontSize:8, color:"var(--text-dim)", letterSpacing:"0.12em", marginTop:-1 }}>
                AI AGENT SECURITY RUNTIME
              </div>
            </div>
          </div>

          <div style={{ width:1, height:24, background:"var(--border)" }} />

          {/* Nav tabs */}
          {["overview","sessions","events","compliance"].map(tab => (
            <button key={tab} onClick={() => { setActiveTab(tab); setSelectedSession(null); }}
              style={{
                background:"none", border:"none", cursor:"pointer", padding:"4px 10px",
                fontFamily:"var(--mono)", fontSize:10, letterSpacing:"0.1em", textTransform:"uppercase",
                color: activeTab===tab ? "var(--amber)" : "var(--text-dim)",
                borderBottom: activeTab===tab ? "1px solid var(--amber)" : "1px solid transparent",
                transition:"all 0.15s", marginBottom:-1,
              }}>
              {tab}
            </button>
          ))}

          <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:16 }}>
            <LiveDot />
            <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)" }}>
              {new Date().toLocaleTimeString("en-US", {hour12:false})}
            </div>
            {criticalEvents > 0 && (
              <div style={{
                fontFamily:"var(--mono)", fontSize:10, color:"var(--red)",
                background:"var(--red-dim)", border:"1px solid var(--red)44",
                padding:"2px 8px", borderRadius:3, animation:"pulse-dot 2s ease-in-out infinite",
              }}>
                ⚠ {criticalEvents} CRITICAL
              </div>
            )}
          </div>
        </div>

        {/* ── MAIN CONTENT ── */}
        <div style={{ flex:1, overflow:"hidden", display:"flex", flexDirection:"column" }}>

          {activeTab === "overview" && (
            <OverviewTab sessions={sessions} events={events} activeSessions={activeSessions}
              totalToolCalls={totalToolCalls} totalBlocked={totalBlocked}
              criticalEvents={criticalEvents} highEvents={highEvents} avgIntegrity={avgIntegrity}
              newEventIds={newEventIds} onSelectSession={(id) => { setSelectedSession(id); setActiveTab("sessions"); }}
            />
          )}

          {activeTab === "sessions" && (
            <SessionsTab sessions={sessions} events={events}
              selected={selectedSession} onSelect={setSelectedSession}
              sessionEvents={sessionEvents} selectedData={selectedSessionData}
            />
          )}

          {activeTab === "events" && (
            <EventsTab events={events} newEventIds={newEventIds} />
          )}

          {activeTab === "compliance" && (
            <ComplianceTab sessions={sessions} events={events} />
          )}
        </div>
      </div>
    </>
  );
}

// ─── OVERVIEW TAB ────────────────────────────────────────────────────────────

function OverviewTab({ sessions, events, activeSessions, totalToolCalls, totalBlocked,
  criticalEvents, highEvents, avgIntegrity, newEventIds, onSelectSession }) {

  const recentEvents = events.slice(0, 12);

  return (
    <div style={{ flex:1, overflow:"hidden", display:"grid",
      gridTemplateColumns:"1fr 340px", gridTemplateRows:"auto 1fr",
      gap:0, padding:16, height:"100%" }}>

      {/* Stat strip */}
      <div style={{ gridColumn:"1/-1", display:"grid", gridTemplateColumns:"repeat(6,1fr)", gap:8, marginBottom:12 }}>
        <StatCard label="Active Sessions" value={activeSessions} sub={`${sessions.length} total`} accent="green" icon="◈" />
        <StatCard label="Tool Calls" value={totalToolCalls.toLocaleString()} sub="intercepted" accent="amber" icon="⟳" />
        <StatCard label="Blocked" value={totalBlocked} sub="calls halted" accent="red" icon="⊘" />
        <StatCard label="Critical Events" value={criticalEvents} sub={`${highEvents} high`} accent={criticalEvents>0?"red":"green"} icon="⚡" />
        <StatCard label="Avg Integrity" value={`${Math.round(avgIntegrity*100)}%`} sub="active sessions" accent={avgIntegrity>0.7?"green":avgIntegrity>0.35?"amber":"red"} icon="◎" />
        <StatCard label="Events (24h)" value={events.length} sub="security events" icon="≡" />
      </div>

      {/* Sessions panel */}
      <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--radius)",
        overflow:"hidden", display:"flex", flexDirection:"column", marginRight:8 }}>
        <div style={{ padding:"10px 14px", borderBottom:"1px solid var(--border)",
          display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
            letterSpacing:"0.1em", textTransform:"uppercase" }}>Active Sessions</span>
          <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--green)" }}>{activeSessions} LIVE</span>
        </div>
        <div style={{ flex:1, overflow:"auto" }}>
          {sessions.filter(s=>s.isActive).slice(0,8).map(s => (
            <div key={s.id} onClick={() => onSelectSession(s.id)}
              style={{ padding:"10px 14px", borderBottom:"1px solid var(--border)",
                cursor:"pointer", transition:"background 0.1s" }}
              onMouseEnter={e => e.currentTarget.style.background="var(--bg3)"}
              onMouseLeave={e => e.currentTarget.style.background="transparent"}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:6 }}>
                <div>
                  <div style={{ fontFamily:"var(--mono)", fontSize:11, color:"var(--text-primary)", marginBottom:2 }}>
                    {s.model}
                  </div>
                  <div style={{ fontFamily:"var(--sans)", fontSize:11, color:"var(--text-secondary)",
                    maxWidth:280, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                    {s.goal}
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:4 }}>
                  <SevDot sev={s.goalIntegrity > 0.7 ? "info" : s.goalIntegrity > 0.35 ? "medium" : "high"} animate />
                </div>
              </div>
              <IntegrityBar score={s.goalIntegrity} />
            </div>
          ))}
        </div>
      </div>

      {/* Live event feed */}
      <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--radius)",
        overflow:"hidden", display:"flex", flexDirection:"column" }}>
        <div style={{ padding:"10px 14px", borderBottom:"1px solid var(--border)",
          display:"flex", alignItems:"center", justifyContent:"space-between" }}>
          <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
            letterSpacing:"0.1em", textTransform:"uppercase" }}>Live Event Feed</span>
          <LiveDot />
        </div>
        <div style={{ flex:1, overflow:"auto" }}>
          {recentEvents.map(ev => {
            const c = SEV_COLORS[ev.sev] || SEV_COLORS.info;
            const isNew = newEventIds.has(ev.id);
            return (
              <div key={ev.id} style={{
                padding:"8px 12px", borderBottom:"1px solid var(--border)",
                display:"flex", flexDirection:"column", gap:3,
                background: isNew ? `${c.bg}` : "transparent",
                animation: isNew ? "slide-in 0.3s ease" : "none",
                borderLeft: isNew ? `2px solid ${c.border}` : "2px solid transparent",
                transition:"background 1s ease",
              }}>
                <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                  <SevDot sev={ev.sev} animate={isNew} />
                  <span style={{ fontFamily:"var(--mono)", fontSize:10, color:c.text, flex:1,
                    overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                    {ev.title}
                  </span>
                  <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)", flexShrink:0 }}>
                    {formatTime(ev.timestamp)}
                  </span>
                </div>
                {ev.cmmc.length > 0 && (
                  <div style={{ display:"flex", gap:3, paddingLeft:13 }}>
                    {ev.cmmc.slice(0,3).map(c => (
                      <span key={c} style={{ fontFamily:"var(--mono)", fontSize:8,
                        color:"var(--text-dim)", background:"var(--bg4)",
                        padding:"1px 4px", borderRadius:2 }}>
                        {c}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─── SESSIONS TAB ────────────────────────────────────────────────────────────

function SessionsTab({ sessions, events, selected, onSelect, sessionEvents, selectedData }) {
  return (
    <div style={{ flex:1, display:"grid", gridTemplateColumns: selected ? "380px 1fr" : "1fr",
      gap:0, overflow:"hidden", padding:16, height:"100%" }}>

      {/* Sessions list */}
      <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--radius)",
        overflow:"hidden", display:"flex", flexDirection:"column",
        marginRight: selected ? 8 : 0 }}>
        <div style={{ padding:"10px 14px", borderBottom:"1px solid var(--border)" }}>
          <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
            letterSpacing:"0.1em", textTransform:"uppercase" }}>
            All Sessions — {sessions.length}
          </span>
        </div>
        <div style={{ flex:1, overflow:"auto" }}>
          {sessions.map(s => {
            const isSelected = selected === s.id;
            const intColor = s.goalIntegrity > 0.7 ? "var(--green)" : s.goalIntegrity > 0.35 ? "var(--amber)" : "var(--red)";
            return (
              <div key={s.id} onClick={() => onSelect(isSelected ? null : s.id)}
                style={{
                  padding:"11px 14px", borderBottom:"1px solid var(--border)",
                  cursor:"pointer", background: isSelected ? "var(--bg4)" : "transparent",
                  borderLeft: isSelected ? "2px solid var(--amber)" : "2px solid transparent",
                  transition:"all 0.1s",
                }}
                onMouseEnter={e => { if(!isSelected) e.currentTarget.style.background="var(--bg3)"; }}
                onMouseLeave={e => { if(!isSelected) e.currentTarget.style.background="transparent"; }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                    <span style={{ width:6, height:6, borderRadius:"50%",
                      background: s.isActive ? "var(--green)" : "var(--text-dim)",
                      animation: s.isActive ? "pulse-dot 1.5s ease-in-out infinite" : "none",
                      boxShadow: s.isActive ? "0 0 5px var(--green)" : "none",
                      display:"inline-block", flexShrink:0 }} />
                    <span style={{ fontFamily:"var(--mono)", fontSize:11, color:"var(--text-primary)" }}>
                      {s.id.toUpperCase().slice(0,12)}
                    </span>
                  </div>
                  <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)" }}>
                    {formatTime(s.startTime)}
                  </span>
                </div>
                <div style={{ fontFamily:"var(--sans)", fontSize:11, color:"var(--text-secondary)",
                  marginBottom:6, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                  {s.goal}
                </div>
                <div style={{ display:"flex", gap:12, alignItems:"center" }}>
                  <IntegrityBar score={s.goalIntegrity} />
                  <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)", whiteSpace:"nowrap" }}>
                    {s.toolCalls} calls
                    {s.blockedCalls > 0 && <span style={{color:"var(--red)"}}> · {s.blockedCalls} blocked</span>}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Session detail */}
      {selected && selectedData && (
        <SessionDetail session={selectedData} events={sessionEvents} />
      )}
    </div>
  );
}

function SessionDetail({ session, events }) {
  const intColor = session.goalIntegrity > 0.7 ? "var(--green)" : session.goalIntegrity > 0.35 ? "var(--amber)" : "var(--red)";

  return (
    <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--radius)",
      overflow:"hidden", display:"flex", flexDirection:"column", animation:"fade-in 0.2s ease" }}>

      {/* Header */}
      <div style={{ padding:"14px 18px", borderBottom:"1px solid var(--border)",
        background:"var(--bg3)" }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start" }}>
          <div>
            <div style={{ fontFamily:"var(--mono)", fontSize:12, color:"var(--text-primary)", marginBottom:4 }}>
              SESSION {session.id.toUpperCase().slice(0,12)}
            </div>
            <div style={{ fontFamily:"var(--sans)", fontSize:13, color:"var(--text-secondary)" }}>
              {session.goal}
            </div>
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
            <span style={{ width:7, height:7, borderRadius:"50%", display:"inline-block",
              background: session.isActive ? "var(--green)" : "var(--text-dim)",
              boxShadow: session.isActive ? "0 0 5px var(--green)" : "none" }} />
            <span style={{ fontFamily:"var(--mono)", fontSize:10,
              color: session.isActive ? "var(--green)" : "var(--text-dim)" }}>
              {session.isActive ? "ACTIVE" : "CLOSED"}
            </span>
          </div>
        </div>
      </div>

      <div style={{ flex:1, overflow:"auto", padding:16 }}>

        {/* Metrics grid */}
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:8, marginBottom:16 }}>
          <div style={{ background:"var(--bg3)", border:"1px solid var(--border)",
            borderRadius:4, padding:"10px 12px" }}>
            <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
              textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:6 }}>Goal Integrity</div>
            <div style={{ fontFamily:"var(--mono)", fontSize:22, fontWeight:600, color:intColor }}>
              {Math.round(session.goalIntegrity*100)}%
            </div>
            <IntegrityBar score={session.goalIntegrity} />
          </div>
          <div style={{ background:"var(--bg3)", border:"1px solid var(--border)",
            borderRadius:4, padding:"10px 12px" }}>
            <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
              textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:6 }}>Tool Calls</div>
            <div style={{ fontFamily:"var(--mono)", fontSize:22, fontWeight:600, color:"var(--text-primary)" }}>
              {session.toolCalls}
            </div>
            {session.blockedCalls > 0 && (
              <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--red)", marginTop:4 }}>
                {session.blockedCalls} blocked
              </div>
            )}
          </div>
          <div style={{ background:"var(--bg3)", border:"1px solid var(--border)",
            borderRadius:4, padding:"10px 12px" }}>
            <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
              textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:6 }}>Anomaly Score</div>
            <div style={{ fontFamily:"var(--mono)", fontSize:22, fontWeight:600,
              color: session.anomalyScore > 0.5 ? "var(--red)" : session.anomalyScore > 0.25 ? "var(--amber)" : "var(--green)" }}>
              {(session.anomalyScore*100).toFixed(0)}%
            </div>
          </div>
        </div>

        {/* Identity block */}
        <div style={{ background:"var(--bg3)", border:"1px solid var(--border)",
          borderRadius:4, padding:"12px 14px", marginBottom:16 }}>
          <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
            textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:10 }}>Session Identity</div>
          {[
            ["Model", session.model],
            ["Initiated By", session.initiator],
            ["Session ID", session.id],
            ["Attestation", session.attestationHash + "..."],
            ["Started", new Date(session.startTime).toLocaleString()],
          ].map(([k,v]) => (
            <div key={k} style={{ display:"flex", gap:12, marginBottom:6 }}>
              <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
                width:100, flexShrink:0 }}>{k}</span>
              <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-primary)",
                overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{v}</span>
            </div>
          ))}
        </div>

        {/* Session events */}
        <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
          textTransform:"uppercase", letterSpacing:"0.1em", marginBottom:8 }}>
          Session Events ({events.length})
        </div>
        {events.length === 0 ? (
          <div style={{ fontFamily:"var(--mono)", fontSize:11, color:"var(--text-dim)",
            textAlign:"center", padding:"20px 0" }}>No events for this session</div>
        ) : (
          events.slice(0,20).map(ev => {
            const c = SEV_COLORS[ev.sev] || SEV_COLORS.info;
            return (
              <div key={ev.id} style={{ display:"flex", gap:8, alignItems:"flex-start",
                padding:"7px 0", borderBottom:"1px solid var(--border)" }}>
                <SevDot sev={ev.sev} />
                <div style={{ flex:1 }}>
                  <div style={{ fontFamily:"var(--mono)", fontSize:10, color:c.text, marginBottom:2 }}>
                    {ev.title}
                  </div>
                  <div style={{ display:"flex", gap:4 }}>
                    {ev.cmmc.map(c => (
                      <span key={c} style={{ fontFamily:"var(--mono)", fontSize:8, color:"var(--text-dim)",
                        background:"var(--bg4)", padding:"1px 4px", borderRadius:2 }}>{c}</span>
                    ))}
                  </div>
                </div>
                <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)", flexShrink:0 }}>
                  {formatTime(ev.timestamp)}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

// ─── EVENTS TAB ──────────────────────────────────────────────────────────────

function EventsTab({ events, newEventIds }) {
  const [filter, setFilter] = useState("all");
  const [search, setSearch] = useState("");

  const filtered = events.filter(ev => {
    if (filter !== "all" && ev.sev !== filter) return false;
    if (search && !ev.title.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  const counts = { critical:0, high:0, medium:0, low:0, info:0 };
  events.forEach(e => { if(counts[e.sev]!==undefined) counts[e.sev]++; });

  return (
    <div style={{ flex:1, overflow:"hidden", display:"flex", flexDirection:"column",
      padding:16, height:"100%" }}>

      {/* Filter bar */}
      <div style={{ display:"flex", gap:8, marginBottom:12, alignItems:"center" }}>
        {["all","critical","high","medium","low","info"].map(s => {
          const c = s === "all" ? null : SEV_COLORS[s];
          const count = s === "all" ? events.length : counts[s];
          return (
            <button key={s} onClick={() => setFilter(s)}
              style={{
                background: filter===s ? (c ? c.badge : "var(--bg4)") : "var(--bg2)",
                border: `1px solid ${filter===s ? (c ? c.border+"66" : "var(--border-bright)") : "var(--border)"}`,
                color: filter===s ? (c ? c.text : "var(--text-primary)") : "var(--text-dim)",
                borderRadius:4, padding:"4px 10px", cursor:"pointer",
                fontFamily:"var(--mono)", fontSize:9, letterSpacing:"0.08em", textTransform:"uppercase",
                display:"flex", alignItems:"center", gap:5, transition:"all 0.15s",
              }}>
              {s !== "all" && <SevDot sev={s} />}
              {s} <span style={{opacity:0.6}}>({count})</span>
            </button>
          );
        })}
        <div style={{ marginLeft:"auto", position:"relative" }}>
          <input value={search} onChange={e=>setSearch(e.target.value)}
            placeholder="Filter events..."
            style={{
              background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:4,
              padding:"4px 10px 4px 28px", fontFamily:"var(--mono)", fontSize:10,
              color:"var(--text-primary)", width:200, outline:"none",
            }} />
          <span style={{ position:"absolute", left:8, top:"50%", transform:"translateY(-50%)",
            color:"var(--text-dim)", fontSize:11, pointerEvents:"none" }}>⌕</span>
        </div>
      </div>

      {/* Events table */}
      <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--radius)",
        overflow:"hidden", flex:1, display:"flex", flexDirection:"column" }}>
        <div style={{ display:"grid", gridTemplateColumns:"80px 80px 1fr 140px 200px 80px",
          padding:"8px 14px", borderBottom:"1px solid var(--border)",
          fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
          letterSpacing:"0.1em", textTransform:"uppercase" }}>
          <span>Severity</span>
          <span>Type</span>
          <span>Title</span>
          <span>Session</span>
          <span>CMMC Controls</span>
          <span style={{textAlign:"right"}}>Time</span>
        </div>
        <div style={{ flex:1, overflow:"auto" }}>
          {filtered.slice(0,150).map(ev => {
            const c = SEV_COLORS[ev.sev] || SEV_COLORS.info;
            const isNew = newEventIds.has(ev.id);
            return (
              <div key={ev.id} style={{
                display:"grid", gridTemplateColumns:"80px 80px 1fr 140px 200px 80px",
                padding:"7px 14px", borderBottom:"1px solid var(--border)",
                alignItems:"center",
                background: isNew ? c.bg : "transparent",
                borderLeft: isNew ? `2px solid ${c.border}` : "2px solid transparent",
                animation: isNew ? "slide-in 0.3s ease" : "none",
                transition:"background 0.8s ease",
              }}>
                <div style={{display:"flex",alignItems:"center",gap:5}}>
                  <SevDot sev={ev.sev} animate={isNew} />
                  <SevBadge sev={ev.sev} />
                </div>
                <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                  {ev.type.replace(/_/g," ")}
                </span>
                <span style={{ fontFamily:"var(--mono)", fontSize:10, color:c.text,
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                  {ev.title}
                </span>
                <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                  {ev.sessionId.toUpperCase().slice(0,10)}
                </span>
                <div style={{display:"flex",gap:3,overflow:"hidden"}}>
                  {ev.cmmc.slice(0,3).map(c => (
                    <span key={c} style={{ fontFamily:"var(--mono)", fontSize:8, color:"var(--text-dim)",
                      background:"var(--bg4)", padding:"1px 5px", borderRadius:2, flexShrink:0 }}>
                      {c}
                    </span>
                  ))}
                </div>
                <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)", textAlign:"right" }}>
                  {formatTime(ev.timestamp)}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// ─── COMPLIANCE TAB ──────────────────────────────────────────────────────────

const CMMC_CONTROLS = [
  { id:"3.1.1", family:"Access Control", title:"Authorized Access Control", status:"covered", evidence:34 },
  { id:"3.1.2", family:"Access Control", title:"Transaction and Function Control", status:"covered", evidence:28 },
  { id:"3.1.3", family:"Access Control", title:"Control CUI Flow", status:"covered", evidence:19 },
  { id:"3.3.1", family:"Audit & Accountability", title:"System Auditing", status:"covered", evidence:187 },
  { id:"3.3.2", family:"Audit & Accountability", title:"User Accountability", status:"covered", evidence:41 },
  { id:"3.5.1", family:"Identification & Auth", title:"User Identification", status:"covered", evidence:23 },
  { id:"3.5.2", family:"Identification & Auth", title:"User Authentication", status:"covered", evidence:23 },
  { id:"3.4.1", family:"Config Management", title:"Baseline Configuration", status:"covered", evidence:55 },
  { id:"3.4.2", family:"Config Management", title:"Configuration Settings", status:"partial", evidence:12 },
  { id:"3.13.1", family:"System & Comms", title:"Boundary Protection", status:"covered", evidence:187 },
  { id:"3.13.3", family:"System & Comms", title:"Security Function Isolation", status:"covered", evidence:7 },
  { id:"3.13.10", family:"System & Comms", title:"Cryptographic Key Management", status:"covered", evidence:23 },
  { id:"3.13.16", family:"System & Comms", title:"CUI at Rest", status:"covered", evidence:14 },
  { id:"3.14.1", family:"System Integrity", title:"Flaw Remediation", status:"partial", evidence:8 },
  { id:"3.14.2", family:"System Integrity", title:"Malicious Code Protection", status:"covered", evidence:31 },
  { id:"3.14.6", family:"System Integrity", title:"Security Alert Monitoring", status:"covered", evidence:55 },
  { id:"3.14.7", family:"System Integrity", title:"Identify Unauthorized Use", status:"covered", evidence:7 },
];

const S1513_ITEMS = [
  { req:"AI system identity & version tracking", status:"active" },
  { req:"Authorized objective registration & drift monitoring", status:"active" },
  { req:"Human oversight & intervention capability", status:"active" },
  { req:"Comprehensive audit trail for AI actions", status:"active" },
  { req:"Detection of adversarial inputs / prompt injection", status:"active" },
  { req:"Cryptographic integrity of AI session records", status:"active" },
  { req:"Credential & sensitive data protection", status:"active" },
  { req:"Configuration baseline enforcement", status:"active" },
  { req:"Multi-agent trust & authentication", status:"active" },
  { req:"Real-time alerting on AI security anomalies", status:"active" },
];

function ComplianceTab({ sessions, events }) {
  const covered = CMMC_CONTROLS.filter(c=>c.status==="covered").length;
  const partial = CMMC_CONTROLS.filter(c=>c.status==="partial").length;
  const s1513Active = S1513_ITEMS.filter(i=>i.status==="active").length;

  return (
    <div style={{ flex:1, overflow:"auto", padding:16, height:"100%" }}>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:8, marginBottom:16 }}>
        <StatCard label="CMMC L2 Controls" value={`${covered}/${CMMC_CONTROLS.length}`} sub={`${partial} partial`} accent="green" icon="✓" />
        <StatCard label="Coverage" value={`${Math.round((covered+partial*0.5)/CMMC_CONTROLS.length*100)}%`} sub="estimated" accent="amber" icon="◎" />
        <StatCard label="Section 1513" value={`${s1513Active}/${S1513_ITEMS.length}`} sub="requirements active" accent="green" icon="§" />
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"1fr 340px", gap:8 }}>

        {/* Controls table */}
        <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden" }}>
          <div style={{ padding:"10px 14px", borderBottom:"1px solid var(--border)",
            fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)", letterSpacing:"0.1em", textTransform:"uppercase" }}>
            NIST SP 800-171 / CMMC Level 2 Control Coverage
          </div>
          <div style={{ overflow:"auto", maxHeight:480 }}>
            {CMMC_CONTROLS.map(ctrl => (
              <div key={ctrl.id} style={{ display:"grid", gridTemplateColumns:"70px 150px 1fr 70px 60px",
                padding:"8px 14px", borderBottom:"1px solid var(--border)", alignItems:"center", gap:8 }}>
                <span style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--amber)", fontWeight:600 }}>{ctrl.id}</span>
                <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)",
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{ctrl.family}</span>
                <span style={{ fontFamily:"var(--sans)", fontSize:11, color:"var(--text-secondary)",
                  overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{ctrl.title}</span>
                <span style={{
                  fontFamily:"var(--mono)", fontSize:8, fontWeight:600, letterSpacing:"0.08em",
                  textTransform:"uppercase", textAlign:"center",
                  color: ctrl.status==="covered" ? "var(--green)" : "var(--amber)",
                  background: ctrl.status==="covered" ? "var(--green-dim)" : "var(--amber-dim)",
                  padding:"2px 6px", borderRadius:3,
                }}>
                  {ctrl.status}
                </span>
                <span style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)", textAlign:"right" }}>
                  {ctrl.evidence}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Section 1513 readiness */}
        <div style={{ background:"var(--bg2)", border:"1px solid var(--border)", borderRadius:"var(--radius)", overflow:"hidden", alignSelf:"start" }}>
          <div style={{ padding:"10px 14px", borderBottom:"1px solid var(--border)" }}>
            <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--text-dim)",
              letterSpacing:"0.1em", textTransform:"uppercase", marginBottom:2 }}>
              NDAA FY2026 § 1513
            </div>
            <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)" }}>
              DoD AI/ML Framework Readiness
            </div>
          </div>
          <div style={{ padding:"4px 0" }}>
            {S1513_ITEMS.map((item,i) => (
              <div key={i} style={{ display:"flex", alignItems:"center", gap:10,
                padding:"8px 14px", borderBottom:"1px solid var(--border)" }}>
                <span style={{ color:"var(--green)", fontSize:11, flexShrink:0 }}>✓</span>
                <span style={{ fontFamily:"var(--sans)", fontSize:11, color:"var(--text-secondary)" }}>
                  {item.req}
                </span>
              </div>
            ))}
          </div>
          <div style={{ padding:"12px 14px", borderTop:"1px solid var(--border)",
            background:"var(--green-dim)" }}>
            <div style={{ fontFamily:"var(--mono)", fontSize:10, color:"var(--green)", fontWeight:600 }}>
              {s1513Active}/{S1513_ITEMS.length} REQUIREMENTS ACTIVE
            </div>
            <div style={{ fontFamily:"var(--mono)", fontSize:9, color:"var(--text-dim)", marginTop:3 }}>
              Status report to Congress due Jun 16, 2026
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
