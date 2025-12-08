# Security Guidelines

## Before Production

- [ ] Change all default passwords
- [ ] Use strong random SECRET_KEY
- [ ] Enable HTTPS (SSL/TLS)
- [ ] Set up firewall rules
- [ ] Enable rate limiting
- [ ] Implement authentication (JWT)
- [ ] Set up audit logging
- [ ] Regular security updates
- [ ] Backup strategy in place

## Environment Variables

Never commit:
- ANTHROPIC_API_KEY
- SECRET_KEY
- DATABASE_PASSWORD

## API Security

1. Implement JWT authentication
2. Add rate limiting (100 requests/minute)
3. Input validation on all endpoints
4. SQL injection prevention (SQLAlchemy handles this)
5. XSS prevention (sanitize outputs)

## Scan Safety

1. Scope enforcement MUST be enabled
2. Never scan without authorization
3. Implement human approval for exploits
4. Log all scanning activities
5. Rate limit scan creation
