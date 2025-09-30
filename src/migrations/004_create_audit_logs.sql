-- Create audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL,
    resource VARCHAR(100),
    resource_id VARCHAR(255),

    -- Event details
    description TEXT,
    outcome VARCHAR(20) NOT NULL, -- success, failure, pending
    risk_level VARCHAR(20) DEFAULT 'low', -- low, medium, high, critical

    -- Context information
    ip_address INET,
    user_agent TEXT,
    session_id UUID,
    request_id VARCHAR(100),

    -- Additional metadata
    metadata JSONB DEFAULT '{}',

    -- Timestamp
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for audit logs
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_risk_level ON audit_logs(risk_level);
CREATE INDEX IF NOT EXISTS idx_audit_logs_outcome ON audit_logs(outcome);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address);

-- Create audit statistics view
CREATE OR REPLACE VIEW audit_statistics AS
SELECT
    event_type,
    COUNT(*) as total_events,
    COUNT(CASE WHEN outcome = 'success' THEN 1 END) as successful_events,
    COUNT(CASE WHEN outcome = 'failure' THEN 1 END) as failed_events,
    COUNT(CASE WHEN risk_level = 'high' THEN 1 END) as high_risk_events,
    COUNT(CASE WHEN risk_level = 'critical' THEN 1 END) as critical_events,
    DATE_TRUNC('day', created_at) as event_date
FROM audit_logs
WHERE created_at >= NOW() - INTERVAL '30 days'
GROUP BY event_type, DATE_TRUNC('day', created_at)
ORDER BY event_date DESC, total_events DESC;
