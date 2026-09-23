import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import { BrowserProvider } from "ethers";

// EIP-4361 is a plain text format, so we build it directly rather than pulling
// in the siwe package, which needs Node's Buffer and breaks in the browser.
// The backend parses and verifies this with its own copy of the library.
function siweMessage(o: {
  domain: string; address: string; statement: string;
  uri: string; chainId: number; nonce: string;
}) {
  return [
    `${o.domain} wants you to sign in with your Ethereum account:`,
    o.address,
    "",
    o.statement,
    "",
    `URI: ${o.uri}`,
    "Version: 1",
    `Chain ID: ${o.chainId}`,
    `Nonce: ${o.nonce}`,
    `Issued At: ${new Date().toISOString()}`,
  ].join("\n");
}
const API = "/api";

export interface Session {
  identityId: string;
  address: string;
  did: string;
  roles: number[];
  clearance: number;
}

/** Thrown for any non-2xx, carrying the backend's reason code so screens can
 *  render the specific refusal rather than a generic failure. */
export class ApiError extends Error {
  constructor(public status: number, public code: string, public detail?: string, public risk?: any) {
    super(code);
  }
}

let token: string | null = sessionStorage.getItem("argus.token");

export async function api<T = any>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !(init.body instanceof FormData)) headers.set("Content-Type", "application/json");

  const res = await fetch(`${API}${path}`, { ...init, headers });
  const type = res.headers.get("content-type") || "";

  if (!res.ok) {
    const body = type.includes("json") ? await res.json().catch(() => ({})) : {};
    throw new ApiError(res.status, body.code || `HTTP_${res.status}`, body.detail, body.risk);
  }
  if (type.includes("json")) return res.json();
  return res as unknown as T;
}

/** Content needs the raw Response so headers (hash, risk score) survive. */
export async function apiRaw(path: string, stepUp = false): Promise<Response> {
  const headers = new Headers();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (stepUp) headers.set("x-step-up", "verified");

  const res = await fetch(`${API}${path}`, { headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(res.status, body.code || `HTTP_${res.status}`, body.detail, body.risk);
  }
  return res;
}

interface Ctx {
  session: Session | null;
  address: string | null;
  connecting: boolean;
  error: { code: string; detail?: string } | null;
  connect: () => Promise<void>;
  signIn: () => Promise<void>;
  signOut: () => void;
}

const SessionCtx = createContext<Ctx>(null as any);
export const useSession = () => useContext(SessionCtx);

const eth = () => (window as any).ethereum;

export function SessionProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(() => {
    const raw = sessionStorage.getItem("argus.session");
    return raw ? JSON.parse(raw) : null;
  });
  const [address, setAddress] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState<{ code: string; detail?: string } | null>(null);

  const signOut = useCallback(() => {
    token = null;
    sessionStorage.removeItem("argus.token");
    sessionStorage.removeItem("argus.session");
    setSession(null);
  }, []);

  const connect = useCallback(async () => {
    if (!eth()) {
      setError({ code: "NO_WALLET", detail: "No wallet extension detected. Install MetaMask to continue." });
      return;
    }
    const accounts: string[] = await eth().request({ method: "eth_requestAccounts" });
    setAddress(accounts[0] ?? null);
  }, []);

  const signIn = useCallback(async () => {
    setConnecting(true);
    setError(null);
    try {
      if (!eth()) throw new ApiError(0, "NO_WALLET", "No wallet extension detected.");
      const provider = new BrowserProvider(eth());
      const signer = await provider.getSigner();
      const who = await signer.getAddress();
      const { chainId } = await provider.getNetwork();

      const { nonce } = await api<{ nonce: string }>("/auth/nonce");
      const message = siweMessage({
        domain: window.location.host,
        address: who,
        statement: "Sign in to ArgusChain",
        uri: window.location.origin,
        chainId: Number(chainId),
        nonce,
      });

      const signature = await signer.signMessage(message);
      const out = await api<{ token: string; session: Session }>("/auth/verify", {
        method: "POST",
        body: JSON.stringify({ message, signature }),
      });

      token = out.token;
      sessionStorage.setItem("argus.token", out.token);
      sessionStorage.setItem("argus.session", JSON.stringify(out.session));
      setSession(out.session);
      setAddress(who);
    } catch (e: any) {
      if (e?.code === 4001 || e?.code === "ACTION_REJECTED") setError({ code: "SIGNATURE_REJECTED", detail: "You declined the signature." });
      else setError({ code: e?.code || "SIGN_IN_FAILED", detail: e?.detail });
    } finally {
      setConnecting(false);
    }
  }, []);

  // Switching MetaMask accounts means acting as a different person, so the old
  // session must not survive: the demo depends on that being unambiguous.
  useEffect(() => {
    if (!eth()) return;
    const onAccounts = (accounts: string[]) => {
      setAddress(accounts[0] ?? null);
      signOut();
    };
    eth().on("accountsChanged", onAccounts);
    eth().request({ method: "eth_accounts" }).then((a: string[]) => setAddress(a[0] ?? null));
    return () => eth().removeListener?.("accountsChanged", onAccounts);
  }, [signOut]);

  const value = useMemo(
    () => ({ session, address, connecting, error, connect, signIn, signOut }),
    [session, address, connecting, error, connect, signIn, signOut]
  );

  return <SessionCtx.Provider value={value}>{children}</SessionCtx.Provider>;
}
