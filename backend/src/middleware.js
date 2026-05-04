import jwt from "jsonwebtoken";
import { config } from "./config.js";

export function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret);
    if (decoded.purpose === "mfa_pending") {
      return res.status(401).json({ error: "Unauthorized" });
    }
    req.user = decoded;
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}
