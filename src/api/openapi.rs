//! OpenAPI documentation generator.
//!
//! Generates a lightweight OpenAPI 3.0 overview for the core REST API routes
//! and the bundled Swagger UI served by the API server.

use axum::response::Html;
use serde_json::{Value, json};

/// Generate a lightweight OpenAPI specification for the core auth and health routes.
pub fn generate_openapi_spec() -> Value {
    json!({
        "openapi": "3.0.3",
        "info": {
            "title": "AuthFramework API",
            "description": "Lightweight generated overview of the core authentication and health routes exposed by AuthFramework",
            "version": env!("CARGO_PKG_VERSION"),
            "contact": {
                "name": "AuthFramework Team",
                "url": "https://github.com/ciresnave/auth-framework"
            },
            "license": {
                "name": "MIT OR Apache-2.0",
                "url": "https://github.com/ciresnave/auth-framework/blob/main/LICENSE"
            }
        },
        "servers": [
            {
                "url": "https://api.example.com/api/v1",
                "description": "Production server"
            },
            {
                "url": "http://localhost:8080/api/v1",
                "description": "Development server"
            }
        ],
        "paths": generate_paths(),
        "components": {
            "schemas": generate_schemas(),
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT"
                },
                "apiKey": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "X-API-Key"
                }
            }
        },
        "security": [
            { "bearerAuth": [] }
        ]
    })
}

fn generate_paths() -> Value {
    json!({
        "/auth/login": {
            "post": {
                "tags": ["Authentication"],
                "summary": "User login",
                "description": "Authenticate user with credentials",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/LoginRequest" }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Login successful",
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/LoginResponse" }
                            }
                        }
                    },
                    "401": {
                        "description": "Invalid credentials",
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/ErrorResponse" }
                            }
                        }
                    }
                }
            }
        },
        "/auth/refresh": {
            "post": {
                "tags": ["Authentication"],
                "summary": "Refresh access token",
                "description": "Get new access token using refresh token",
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/RefreshRequest" }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Token refreshed successfully",
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/RefreshResponse" }
                            }
                        }
                    }
                }
            }
        },
        "/auth/logout": {
            "post": {
                "tags": ["Authentication"],
                "summary": "User logout",
                "description": "Invalidate user session and tokens",
                "security": [{ "bearerAuth": [] }],
                "requestBody": {
                    "required": false,
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/LogoutRequest" }
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "Logout successful",
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/MessageResponse" }
                            }
                        }
                    }
                }
            }
        },
        "/health": {
            "get": {
                "tags": ["System"],
                "summary": "Health check",
                "description": "Get system health status",
                "responses": {
                    "200": {
                        "description": "System is healthy",
                        "content": {
                            "application/json": {
                                "schema": { "$ref": "#/components/schemas/HealthResponse" }
                            }
                        }
                    }
                }
            }
        }
    })
}

fn generate_schemas() -> Value {
    json!({
        "LoginRequest": {
            "type": "object",
            "required": ["username", "password"],
            "properties": {
                "username": {
                    "type": "string",
                    "description": "User's username or email"
                },
                "password": {
                    "type": "string",
                    "format": "password",
                    "description": "User's password"
                },
                "mfa_code": {
                    "type": "string",
                    "description": "Multi-factor authentication code (if required)"
                },
                "challenge_id": {
                    "type": "string",
                    "description": "Pending MFA challenge identifier returned by a previous login attempt"
                },
                "remember_me": {
                    "type": "boolean",
                    "default": false,
                    "description": "Extended session duration"
                }
            }
        },
        "LoginResponse": {
            "type": "object",
            "properties": {
                "success": { "type": "boolean" },
                "data": {
                    "type": "object",
                    "properties": {
                        "access_token": { "type": "string" },
                        "refresh_token": { "type": "string" },
                        "token_type": { "type": "string", "example": "Bearer" },
                        "expires_in": { "type": "integer" },
                        "user": { "$ref": "#/components/schemas/UserInfo" },
                        "login_risk_level": {
                            "type": "string",
                            "enum": ["low", "medium", "high", "critical"]
                        },
                        "security_warnings": {
                            "type": "array",
                            "items": { "type": "string" }
                        }
                    }
                }
            }
        },
        "RefreshResponse": {
            "type": "object",
            "properties": {
                "success": { "type": "boolean" },
                "data": {
                    "type": "object",
                    "properties": {
                        "access_token": { "type": "string" },
                        "token_type": { "type": "string", "example": "Bearer" },
                        "expires_in": { "type": "integer" }
                    }
                }
            }
        },
        "LogoutRequest": {
            "type": "object",
            "properties": {
                "refresh_token": {
                    "type": "string",
                    "description": "Optional refresh token to revoke alongside the access token"
                }
            }
        },
        "UserInfo": {
            "type": "object",
            "properties": {
                "id": { "type": "string" },
                "username": { "type": "string" },
                "roles": {
                    "type": "array",
                    "items": { "type": "string" }
                },
                "permissions": {
                    "type": "array",
                    "items": { "type": "string" }
                }
            }
        },
        "ErrorResponse": {
            "type": "object",
            "properties": {
                "success": { "type": "boolean", "example": false },
                "error": {
                    "type": "object",
                    "properties": {
                        "code": { "type": "string" },
                        "message": { "type": "string" },
                        "details": { "type": "object" }
                    }
                }
            }
        },
        "MessageResponse": {
            "type": "object",
            "properties": {
                "success": { "type": "boolean" },
                "message": { "type": "string" }
            }
        },
        "HealthResponse": {
            "type": "object",
            "properties": {
                "status": { "type": "string", "enum": ["healthy", "degraded", "unhealthy"] },
                "timestamp": { "type": "string", "format": "date-time" },
                "checks": {
                    "type": "object",
                    "additionalProperties": {
                        "type": "object",
                        "properties": {
                            "status": { "type": "string" },
                            "details": { "type": "object" }
                        }
                    }
                }
            }
        }
    })
}

/// Serve the generated OpenAPI specification as JSON.
pub async fn serve_openapi_json() -> axum::Json<Value> {
    axum::Json(generate_openapi_spec())
}

/// Generate Swagger UI HTML.
pub fn generate_swagger_ui() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AuthFramework API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui.css" />
    <style>
        html { box-sizing: border-box; overflow: -moz-scrollbars-vertical; overflow-y: scroll; }
        *, *:before, *:after { box-sizing: inherit; }
        body { margin:0; background: #fafafa; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-bundle.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@4.15.5/swagger-ui-standalone-preset.js"></script>
    <script>
        window.onload = function() {
            const ui = SwaggerUIBundle({
                url: '/api/openapi.json',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                layout: "StandaloneLayout"
            });
        };
    </script>
</body>
</html>"#.to_string()
}

/// Serve the bundled Swagger UI.
pub async fn serve_swagger_ui() -> Html<String> {
    Html(generate_swagger_ui())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openapi_spec_generation() {
        let spec = generate_openapi_spec();
        assert_eq!(spec["openapi"], "3.0.3");
        assert_eq!(spec["info"]["title"], "AuthFramework API");
        assert!(spec["paths"].is_object());
        assert!(spec["components"]["schemas"].is_object());
    }

    #[test]
    fn test_swagger_ui_generation() {
        let html = generate_swagger_ui();
        assert!(html.contains("swagger-ui"));
        assert!(html.contains("/api/openapi.json"));
    }
}
