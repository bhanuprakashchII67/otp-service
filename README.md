# OTP Service

Reusable OTP sender and verifier for sensitive app actions.

## Endpoint

POST `/functions/v1/otp`

The function requires a valid Supabase Auth user JWT.

### Send OTP

```json
{
  "action": "send",
  "purpose": "change_password",
  "phone": "+919876543210",
  "email": "user@example.com"
}
```

Supported purposes:
- `change_password`
- `confirm_email`
- `confirm_phone`
- `delete_account`
- `sensitive_action`

At least one destination is required. When both are supplied, the same OTP is sent to both.

### Verify OTP

```json
{
  "action": "verify",
  "purpose": "change_password",
  "otp": "123456"
}
```

The authenticated user's ID comes from the Supabase Auth JWT; callers cannot choose another user's `user_id`.

## Security behavior

- 6-digit cryptographically secure OTP.
- 5-minute expiration.
- HMAC-SHA-256 OTP storage; OTPs are never stored in plaintext.
- Maximum 5 verification attempts.
- 60-second resend cooldown.
- OTPs are single-use.
- OTP purpose is bound into the verification hash.
- Database access is server-side only; `otp_challenges` has RLS enabled and public client roles have no table privileges.
- Provider credentials are environment secrets and are not committed.

## Provider integration

This repository is provider-neutral. Add the provider endpoints and tokens later:

```env
WHATSAPP_PROVIDER_URL=
WHATSAPP_PROVIDER_TOKEN=
EMAIL_PROVIDER_URL=
EMAIL_PROVIDER_TOKEN=
OTP_HMAC_SECRET=
```

The provider adapter currently sends:
- WhatsApp: `{ "to": phone, "otp": otp, "purpose": purpose }`
- Email: `{ "to": email, "subject": "...", "text": "..." }`

Replace those request payloads when you choose the actual WhatsApp/email vendor.

## Deployment

Deploy the `otp` Edge Function to the Supabase project linked to this repository.

Do not commit real provider tokens or `OTP_HMAC_SECRET`.
