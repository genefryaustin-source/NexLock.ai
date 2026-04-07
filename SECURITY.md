
# Security Notes

## Authentication
- Passwords hashed with bcrypt (12 rounds).
- Enforced password policy (12+ chars, upper/lower/number/symbol).
- First login forces password change.

## Password Reset
- SuperAdmin generates one-time reset token with expiry.
- Tokens are stored and marked used upon consumption.

## Tenant Isolation
- All tenant-scoped operations are filtered by tenant_id (query-level RLS).
- SuperAdmin must explicitly select tenant; TenantAdmin/Auditor are locked.

## Audit Logging
- Append-only `audit_log` captures evidence + admin actions for SOC 2 auditability.
