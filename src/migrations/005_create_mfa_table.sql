-- Create MFA table
CREATE TABLE IF NOT EXISTS user_mfa (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    method_type VARCHAR(50) NOT NULL, -- totp, sms, email, backup_codes
    
    -- Method-specific data
    secret_key VARCHAR(255), -- For TOTP
    phone_number VARCHAR(20), -- For SMS
    email_address VARCHAR(255), -- For email MFA
    backup_codes JSONB, -- For backup codes
    
    -- Configuration
    is_enabled BOOLEAN DEFAULT true,
    is_verified BOOLEAN DEFAULT false,
    recovery_questions JSONB DEFAULT '{}',
    
    -- Usage tracking
    last_used TIMESTAMP WITH TIME ZONE,
    use_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    
    -- Timestamps
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(user_id, method_type)
);

-- Create MFA challenges table
CREATE TABLE IF NOT EXISTS mfa_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    challenge_code VARCHAR(10) NOT NULL,
    method_type VARCHAR(50) NOT NULL,
    
    -- Challenge state
    is_used BOOLEAN DEFAULT false,
    attempts INTEGER DEFAULT 0,
    max_attempts INTEGER DEFAULT 3,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    
    -- Lifecycle
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE
);

-- Create MFA recovery codes table
CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    
    -- Usage tracking
    is_used BOOLEAN DEFAULT false,
    used_at TIMESTAMP WITH TIME ZONE,
    used_ip INET,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_user_mfa_user_id ON user_mfa(user_id);
CREATE INDEX IF NOT EXISTS idx_user_mfa_method_type ON user_mfa(method_type);
CREATE INDEX IF NOT EXISTS idx_user_mfa_enabled ON user_mfa(is_enabled);

CREATE INDEX IF NOT EXISTS idx_mfa_challenges_user_id ON mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_code ON mfa_challenges(challenge_code);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires ON mfa_challenges(expires_at);

CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_user_id ON mfa_recovery_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_recovery_codes_used ON mfa_recovery_codes(is_used);

-- Add updated_at trigger
CREATE TRIGGER update_user_mfa_updated_at BEFORE UPDATE ON user_mfa
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Function to cleanup expired MFA challenges
CREATE OR REPLACE FUNCTION cleanup_expired_mfa_challenges()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM mfa_challenges 
    WHERE expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;
