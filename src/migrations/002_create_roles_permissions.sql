-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    parent_role_id UUID REFERENCES roles(id),
    is_system BOOLEAN DEFAULT false,

    -- Role metadata
    priority INTEGER DEFAULT 0,
    max_users INTEGER,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create permissions table
CREATE TABLE IF NOT EXISTS permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    resource VARCHAR(100) NOT NULL,
    action VARCHAR(50) NOT NULL,

    -- Permission metadata
    is_system BOOLEAN DEFAULT false,
    conditions JSONB DEFAULT '{}',

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create role_permissions junction table
CREATE TABLE IF NOT EXISTS role_permissions (
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),

    PRIMARY KEY (role_id, permission_id)
);

-- Create user_roles junction table
CREATE TABLE IF NOT EXISTS user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    assigned_by UUID REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE,

    PRIMARY KEY (user_id, role_id)
);

-- Create direct user permissions (overrides)
CREATE TABLE IF NOT EXISTS user_permissions (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    granted BOOLEAN NOT NULL, -- true = grant, false = deny
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    granted_by UUID REFERENCES users(id),
    expires_at TIMESTAMP WITH TIME ZONE,

    PRIMARY KEY (user_id, permission_id)
);

-- Create permission groups for easier management
CREATE TABLE IF NOT EXISTS permission_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,

    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS permission_group_permissions (
    group_id UUID REFERENCES permission_groups(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,

    PRIMARY KEY (group_id, permission_id)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name);
CREATE INDEX IF NOT EXISTS idx_roles_parent ON roles(parent_role_id);
CREATE INDEX IF NOT EXISTS idx_permissions_resource_action ON permissions(resource, action);
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_user_id ON user_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_role_id ON role_permissions(role_id);

-- Add updated_at triggers
CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_permissions_updated_at BEFORE UPDATE ON permissions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_permission_groups_updated_at BEFORE UPDATE ON permission_groups
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default roles and permissions
INSERT INTO roles (name, description, is_system) VALUES
    ('admin', 'System administrator with full access', true),
    ('user', 'Standard user with basic permissions', true),
    ('moderator', 'Content moderator with elevated permissions', true)
ON CONFLICT (name) DO NOTHING;

-- Insert basic permissions
INSERT INTO permissions (name, description, resource, action, is_system) VALUES
    ('user.read', 'Read user information', 'user', 'read', true),
    ('user.write', 'Create and update users', 'user', 'write', true),
    ('user.delete', 'Delete users', 'user', 'delete', true),
    ('role.read', 'Read role information', 'role', 'read', true),
    ('role.write', 'Create and update roles', 'role', 'write', true),
    ('role.delete', 'Delete roles', 'role', 'delete', true),
    ('permission.read', 'Read permission information', 'permission', 'read', true),
    ('permission.write', 'Create and update permissions', 'permission', 'write', true),
    ('permission.delete', 'Delete permissions', 'permission', 'delete', true),
    ('audit.read', 'Read audit logs', 'audit', 'read', true),
    ('system.admin', 'Full system administration', 'system', 'admin', true)
ON CONFLICT (name) DO NOTHING;

-- Assign permissions to roles
WITH admin_role AS (SELECT id FROM roles WHERE name = 'admin'),
     user_role AS (SELECT id FROM roles WHERE name = 'user'),
     moderator_role AS (SELECT id FROM roles WHERE name = 'moderator')
INSERT INTO role_permissions (role_id, permission_id)
SELECT admin_role.id, p.id FROM admin_role, permissions p WHERE p.is_system = true
UNION ALL
SELECT user_role.id, p.id FROM user_role, permissions p WHERE p.name = 'user.read'
UNION ALL
SELECT moderator_role.id, p.id FROM moderator_role, permissions p
WHERE p.name IN ('user.read', 'user.write', 'audit.read')
ON CONFLICT (role_id, permission_id) DO NOTHING;
