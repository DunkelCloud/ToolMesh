# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- REST Proxy Mode via DADL (Declarative API Definition Language) — connect any REST API without writing an MCP server
- DADL parser with support for bearer, API key, OAuth2 client credentials, and session-based authentication
- Built-in error handling with configurable retry strategies (exponential backoff, retry on 429/5xx)
- Manual pagination support for REST APIs
- PII filter for redacting sensitive data in tool responses
- Embedded credential store (environment variable based)
- MCP backend adapter for connecting existing MCP servers
- TypeScript-based custom tool definitions
- Session-based authentication with automatic re-login on 401
- Docker Compose setup for full-stack deployment

### Security
- Input validation and sanitization for all tool parameters
- Credential isolation — secrets never exposed in tool responses or logs
