export const ROLE = { ADMIN: 1, MANAGER: 2, AUDITOR: 3, USER: 4, SECURITY_OFFICER: 5 } as const;
export const ROLE_IDS = [1, 2, 3, 4, 5];

export const STATUS = { NONE: 0, ACTIVE: 1, SUSPENDED: 2, REVOKED: 3 } as const;

export const P = {
  LIST: 1 << 0, READ_META: 1 << 1, READ: 1 << 2, DOWNLOAD: 1 << 3,
  WRITE: 1 << 4, SHARE: 1 << 5, ADMIN: 1 << 6, AUDIT: 1 << 7,
} as const;