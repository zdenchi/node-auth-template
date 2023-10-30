# TypeScript, Express.js, PostgreSQL (Prisma ORM), JWT Auth Template

## TO-DO

- [x] Signup
- [x] Login
- [x] Logout
- [x] Refresh tokens + invalidate old token
- [x] Get user data + isAuth middleware
- [x] Change user password
- [x] Send email service
- [x] Send SMS service
- [x] Forgot + reset password
- [x] Update phone or email
- [x] Email verification
- [x] Phone verification
- [x] Validate user input
- [ ] <s>Passwordless auth</s>
- [x] Social auth google
- [ ] User impersonation
- [ ] Fail login limit
- [ ] Requests limit
- [ ] Migrate refresh_tokens table to redis

[Про токены, JSON Web Tokens (JWT), аутентификацию и авторизацию. Token-Based Authentication](https://gist.github.com/zmts/802dc9c3510d79fd40f9dc38a12bccfc)

[Контрольний список безпеки API](https://github.com/shieldfy/API-Security-Checklist/blob/master/README-uk.md)

[Google Cloud Console](https://console.cloud.google.com/apis/dashboard)

Generate google auth url on the client side
```typescript
function getGoogleUrl(): string {
  const rootUrl = `https://accounts.google.com/o/oauth2/v2/auth`;

  const options = {
    redirect_uri: process.env.GOOGLE_REDIRECT,
    client_id: process.env.GOOGLE_CLIENT_ID,
    access_type: 'offline',
    response_type: 'code',
    prompt: 'consent',
    scope: [
      'https://www.googleapis.com/auth/userinfo.profile',
      'https://www.googleapis.com/auth/userinfo.email',
    ].join(' '),
    state: '/',
  } as Record<string, string>;

  const qs = new URLSearchParams(options);

  return `${rootUrl}?${qs}`;
}
```
