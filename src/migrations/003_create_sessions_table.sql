-- Create sessions table for session management
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    
    -- Session metadata
    device_info JSONB DEFAULT '{}',
    user_agent TEXT,
    ip_address INET,
    location JSONB DEFAULT '{}',
    
    -- Security tracking
    risk_score DECIMAL(3,2) DEFAULT 0.00,
    security_flags JSONB DEFAULT '{}',
    is_suspicious BOOLEAN DEFAULT false,
    
    -- Session lifecycle
    is_active BOOLEAN DEFAULT true,
    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    terminated_at TIMESTAMP WITH TIME ZONE,
    termination_reason VARCHAR(100)
);

-- Create refresh tokens table
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) UNIQUE NOT NULL,
    
    -- Token metadata
    device_fingerprint VARCHAR(255),
    family VARCHAR(100), -- Token family for rotation
    
    -- Lifecycle
    is_revoked BOOLEAN DEFAULT false,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revocation_reason VARCHAR(100),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_used TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create device tracking table
CREATE TABLE IF NOT EXISTS user_devices (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,
    
    -- Device information
    device_name VARCHAR(255),
    device_type VARCHAR(50), -- mobile, desktop, tablet, etc.
    os VARCHAR(100),
    browser VARCHAR(100),
    
    -- Trust and security
    is_trusted BOOLEAN DEFAULT false,
    trust_score DECIMAL(3,2) DEFAULT 0.00,
    risk_indicators JSONB DEFAULT '{}',
    
    -- Usage tracking
    first_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    total_sessions INTEGER DEFAULT 0,
    
    -- Location tracking
    last_location JSONB DEFAULT '{}',
    locations_history JSONB DEFAULT '[]',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(user_id, device_fingerprint)
);

-- Create session events for detailed tracking
CREATE TABLE IF NOT EXISTS session_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES sessions(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    
    event_type VARCHAR(50) NOT NULL, -- login, logout, refresh, suspicious_activity, etc.
    event_data JSONB DEFAULT '{}',
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create active sessions view for easy querying
CREATE OR REPLACE VIEW active_sessions AS
SELECT 
    s.*,
    u.email,
    u.username,
    ud.device_name,
    ud.device_type,
    ud.is_trusted
FROM sessions s
JOIN users u ON s.user_id = u.id
LEFT JOIN user_devices ud ON s.user_id = ud.user_id 
    AND s.device_info->>'fingerprint' = ud.device_fingerprint
WHERE s.is_active = true 
    AND s.expires_at > NOW()
    AND s.terminated_at IS NULL;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity ON sessions(last_activity);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_session_id ON refresh_tokens(session_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON refresh_tokens(family);

CREATE INDEX IF NOT EXISTS idx_user_devices_user_id ON user_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_user_devices_fingerprint ON user_devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_user_devices_trusted ON user_devices(is_trusted);

CREATE INDEX IF NOT EXISTS idx_session_events_session_id ON session_events(session_id);
CREATE INDEX IF NOT EXISTS idx_session_events_user_id ON session_events(user_id);
CREATE INDEX IF NOT EXISTS idx_session_events_type ON session_events(event_type);
CREATE INDEX IF NOT EXISTS idx_session_events_created_at ON session_events(created_at);

-- Add updated_at trigger for user_devices
CREATE TRIGGER update_user_devices_updated_at BEFORE UPDATE ON user_devices
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to cleanup expired sessions
CREATE OR REPLACE FUNCTION cleanup_expired_sessions()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Mark expired sessions as inactive
    UPDATE sessions 
    SET is_active = false, 
        terminated_at = NOW(),
        termination_reason = 'expired'
    WHERE expires_at < NOW() 
        AND is_active = true
        AND terminated_at IS NULL;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Revoke associated refresh tokens
    UPDATE refresh_tokens 
    SET is_revoked = true,
        revoked_at = NOW(),
        revocation_reason = 'session_expired'
    WHERE session_id IN (
        SELECT id FROM sessions 
        WHERE expires_at < NOW() 
            AND terminated_at IS NOT NULL
    ) AND is_revoked = false;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to update device last seen
CREATE OR REPLACE FUNCTION update_device_last_seen()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE user_devices 
    SET last_seen = NEW.last_activity,
        total_sessions = total_sessions + CASE WHEN TG_OP = 'INSERT' THEN 1 ELSE 0 END
    WHERE user_id = NEW.user_id 
        AND device_fingerprint = NEW.device_info->>'fingerprint';
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to update device tracking on session activity
CREATE TRIGGER update_device_on_session_activity 
    AFTER INSERT OR UPDATE OF last_activity ON sessions
    FOR EACH ROW 
    WHEN (NEW.device_info->>'fingerprint' IS NOT NULL)
    EXECUTE FUNCTION update_device_last_seen();
