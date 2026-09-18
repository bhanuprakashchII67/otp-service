import { createClient } from "npm:@supabase/supabase-js@2";

const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
const publishableKey = Deno.env.get("SUPABASE_PUBLISHABLE_KEY") ?? (() => { const keys = Deno.env.get("SUPABASE_PUBLISHABLE_KEYS"); if (!keys) return ""; try { return JSON.parse(keys).default ?? ""; } catch { return ""; } })();
const secretKey = Deno.env.get("SUPABASE_SECRET_KEY") ?? (() => { const keys = Deno.env.get("SUPABASE_SECRET_KEYS"); if (!keys) return ""; try { return JSON.parse(keys).default ?? ""; } catch { return ""; } })();
const admin = createClient(supabaseUrl, secretKey);

const OTP_TTL_MS = 5 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const RESEND_COOLDOWN_MS = 60 * 1000;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Content-Type": "application/json",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: corsHeaders,
  });

function makeOtp(): string {
  const limit = Math.floor(0x1_0000_0000 / 1_000_000) * 1_000_000;
  const value = new Uint32Array(1);

  do {
    crypto.getRandomValues(value);
  } while (value[0] >= limit);

  return String(value[0] % 1_000_000).padStart(6, "0");
}

async function hmac(value: string): Promise<string> {
  const secret = Deno.env.get("OTP_HMAC_SECRET");
  if (!secret) throw new Error("OTP_HMAC_SECRET is not configured");

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value),
  );

  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );

  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sendWhatsApp(phone: string, otp: string, purpose: string) {
  const url = Deno.env.get("WHATSAPP_PROVIDER_URL");
  const token = Deno.env.get("WHATSAPP_PROVIDER_TOKEN");

  if (!url || !token) throw new Error("WhatsApp provider not configured");

  const result = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${token}`,
    },
    body: JSON.stringify({ to: phone, otp, purpose }),
  });

  if (!result.ok) {
    throw new Error(`WhatsApp delivery failed: ${result.status}`);
  }
}

async function sendEmail(email: string, otp: string, purpose: string) {
  const url = Deno.env.get("EMAIL_PROVIDER_URL");
  const token = Deno.env.get("EMAIL_PROVIDER_TOKEN");

  if (!url || !token) throw new Error("Email provider not configured");

  const result = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "authorization": `Bearer ${token}`,
    },
    body: JSON.stringify({
      to: email,
      subject: "Your verification code",
      text: `Your OTP for ${purpose} is ${otp}. It expires in 5 minutes.`,
    }),
  });

  if (!result.ok) {
    throw new Error(`Email delivery failed: ${result.status}`);
  }
}

async function authenticateUser(request: Request) {
  if (!supabaseUrl || !publishableKey) throw new Error("Supabase publishable key is not configured");
  const authorization = request.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) return null;
  const userClient = createClient(supabaseUrl, publishableKey, { global: { headers: { Authorization: authorization } } });
  const { data, error } = await userClient.auth.getUser();
  if (error || !data.user) return null;
  return data.user;
}

Deno.serve(async (request) => {
    if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
    if (request.method !== "POST") return json({ error: "Method not allowed" }, 405);

    try {
      const user = await authenticateUser(request);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const userId = user.id;

      const body = await request.json();
      const action = body?.action;
      const purpose = String(body?.purpose ?? "").trim();

      if (!purpose) return json({ error: "purpose is required" }, 400);

      if (action === "send") {
        const phone = typeof user.phone === "string" ? user.phone.trim() : "";
        const email = typeof user.email === "string" ? user.email.trim() : "";
        if (!phone && !email) {
          return json({ error: "No email or phone is registered for this account" }, 400);
        }

        const { data: latest, error: latestError } = await admin
          .from("otp_challenges")
          .select("created_at")
          .eq("user_id", userId)
          .eq("purpose", purpose)
          .is("used_at", null)
          .order("created_at", { ascending: false })
          .limit(1)
          .maybeSingle();

        if (latestError) throw latestError;

        if (
          latest &&
          Date.now() - new Date(latest.created_at).getTime() < RESEND_COOLDOWN_MS
        ) {
          return json({ ok: true, message: "OTP request accepted" });
        }

        const otp = makeOtp();
        const primaryDestination = phone || email;
        const channel = phone && email ? "both" : phone ? "whatsapp" : "email";

        const otpHash = await hmac(`${userId}:${purpose}:${otp}`);
        const destinationHash = await sha256(primaryDestination);

        const { data: challenge, error: insertError } = await admin
          .from("otp_challenges")
          .insert({
            user_id: userId,
            purpose,
            channel,
            destination_hash: destinationHash,
            otp_hash: otpHash,
            expires_at: new Date(Date.now() + OTP_TTL_MS).toISOString(),
            attempts: 0,
            max_attempts: MAX_ATTEMPTS,
          })
          .select("id")
          .single();

        if (insertError) throw insertError;

        try {
          if (phone) await sendWhatsApp(phone, otp, purpose);
          if (email) await sendEmail(email, otp, purpose);
        } catch (deliveryError) {
          await admin
            .from("otp_challenges")
            .update({ used_at: new Date().toISOString() })
            .eq("id", challenge.id);
          throw deliveryError;
        }

        return json({ ok: true, message: "OTP request accepted" });
      }

      if (action === "verify") {
        const otp = String(body?.otp ?? "");
        if (!/^\d{6}$/.test(otp)) return json({ verified: false }, 400);

        const { data: challenge, error: challengeError } = await admin
          .from("otp_challenges")
          .select("*")
          .eq("user_id", userId)
          .eq("purpose", purpose)
          .is("used_at", null)
          .gt("expires_at", new Date().toISOString())
          .order("created_at", { ascending: false })
          .limit(1)
          .maybeSingle();

        if (challengeError) throw challengeError;
        if (!challenge || challenge.attempts >= challenge.max_attempts) {
          return json({ verified: false });
        }

        const candidateHash = await hmac(`${userId}:${purpose}:${otp}`);
        const nextAttempts = challenge.attempts + 1;

        if (candidateHash !== challenge.otp_hash) {
          await admin
            .from("otp_challenges")
            .update({ attempts: nextAttempts })
            .eq("id", challenge.id);

          return json({ verified: false });
        }

        const { error: updateError } = await admin
          .from("otp_challenges")
          .update({
            used_at: new Date().toISOString(),
            attempts: nextAttempts,
          })
          .eq("id", challenge.id)
          .is("used_at", null);

        if (updateError) throw updateError;

        return json({ verified: true });
      }

      return json({ error: "Invalid action" }, 400);
    } catch (error) {
      console.error(error);
      return json({ error: "Internal server error" }, 500);
    }
});
