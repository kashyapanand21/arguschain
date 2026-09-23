import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export interface Session {
  identityId: string;
  address: string;
  did: string;
  roles: number[];
  clearance: number;
}

declare global {
  namespace Express {
    interface Request { user?: Session }
  }
}

export function jwtSecret(): string {
  const s = process.env.JWT_SECRET;
  if (!s) throw new Error("JWT_SECRET is not set in backend/.env");
  return s;
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) return res.status(401).json({ code: "NO_SESSION" });
  try {
    req.user = jwt.verify(header.slice(7), jwtSecret()) as Session;
    next();
  } catch {
    res.status(401).json({ code: "SESSION_EXPIRED" });
  }
}