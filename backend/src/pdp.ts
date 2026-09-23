import { contracts } from "./chain";
import { P, ROLE } from "./constants";
import type { Session } from "./middleware/auth";

export interface Decision {
  allow: boolean;
  code: string;
  status: number;      // HTTP status for a denial
  effective: number;   // the resolved mask, for the Effective Access trace
  detail?: string;
}

// Auditor and Security Officer can never hold content bits (INV-8).
// A refusal for them is a separation-of-duty event, not a missing grant.
const NO_CONTENT_ROLES = [ROLE.AUDITOR, ROLE.SECURITY_OFFICER];
const CONTENT_BITS = P.READ | P.DOWNLOAD | P.WRITE;

export async function authorize(session: Session, tokenId: string, bit: number): Promise<Decision> {
  const identityId = BigInt(session.identityId);
  const resourceId = "0x" + BigInt(tokenId).toString(16).padStart(64, "0");

  if (!(await contracts.assets.exists(tokenId))) {
    return { allow: false, code: "ASSET_NOT_FOUND", status: 404, effective: 0 };
  }
  // live, never from the JWT: a suspension takes effect immediately
  if (!(await contracts.identity.isActive(identityId))) {
    return { allow: false, code: "IDENTITY_INACTIVE", status: 403, effective: 0 };
  }

  const effective = Number(await contracts.access.effectivePermissionsForIdentity(resourceId, identityId));
  if (effective & bit) return { allow: true, code: "ALLOW", status: 200, effective };

  return { ...(await explain(session, identityId, resourceId, tokenId, bit, effective)), effective };
}

async function explain(
  session: Session, identityId: bigint, resourceId: string,
  tokenId: string, bit: number, effective: number
): Promise<Omit<Decision, "effective">> {
  // 1. Separation of duty: this role may never hold this bit, whatever the ACL says
  if (bit & CONTENT_BITS && session.roles.some((r) => NO_CONTENT_ROLES.includes(r as any))) {
    return { allow: false, code: "SOD_VIOLATION", status: 403,
      detail: "This role may never read asset content." };
  }

  // 2. Mandatory access control: clearance below classification
  const classification = Number(await contracts.assets.classificationOf(tokenId));
  if (session.clearance < classification) {
    return { allow: false, code: "INSUFFICIENT_CLEARANCE",
      status: 404, // never confirm that a higher-classified asset exists
      detail: classification === session.clearance + 1 ? "Locked entry: request access." : undefined };
    }
    
      // 3. ACE-level causes, read only to choose the message
  const now = Math.floor(Date.now() / 1000);
  const principals: string[] = await contracts.access.principalsOf(identityId);
  let denied = false, expired = false, found = false;

  for (const principal of principals) {
    const ace = await contracts.access.getAce(resourceId, principal);
    if (ace.allowMask === 0n && ace.denyMask === 0n) continue;
    found = true;
    if (Number(ace.denyMask) & bit) denied = true;
    if (ace.expiresAt !== 0n && now >= Number(ace.expiresAt) && Number(ace.allowMask) & bit) expired = true;
  }

  if (denied) return { allow: false, code: "EXPLICIT_DENY", status: 403 };
  if (expired) return { allow: false, code: "ACE_EXPIRED", status: 403 };
  if (!found) return { allow: false, code: "NO_ACE_ON_ASSET", status: 403 };

  return { allow: false, code: "PERMISSION_BIT_MISSING", status: 403,
    detail: `Holds 0x${effective.toString(16)}, missing 0x${bit.toString(16)}.` };
}