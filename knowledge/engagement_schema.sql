-- protoPen engagement audit trail schema

CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    scope_json TEXT,
    mode TEXT NOT NULL,
    max_phase TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    outcome TEXT
);

CREATE INDEX IF NOT EXISTS idx_engagements_name ON engagements(name);
CREATE INDEX IF NOT EXISTS idx_engagements_started ON engagements(started_at);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    target_ip TEXT,
    target_mac TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS tool_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    tool_name TEXT NOT NULL,
    action TEXT,
    args_json TEXT,
    result_summary TEXT,
    success INTEGER NOT NULL DEFAULT 1,
    blocked INTEGER NOT NULL DEFAULT 0,
    block_reason TEXT,
    duration_ms INTEGER,
    phase TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_engagement ON tool_calls(engagement_id);
CREATE INDEX IF NOT EXISTS idx_tool_calls_tool ON tool_calls(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_calls_created ON tool_calls(created_at);

CREATE TABLE IF NOT EXISTS phase_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    from_phase TEXT,
    to_phase TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_phase_transitions_engagement ON phase_transitions(engagement_id);

CREATE TABLE IF NOT EXISTS approval_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER REFERENCES engagements(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT,
    evidence TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    channel TEXT,
    responded_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_engagement ON approval_log(engagement_id);
CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_log(status);
