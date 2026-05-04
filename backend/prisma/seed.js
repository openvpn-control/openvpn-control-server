import bcrypt from "bcryptjs";
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

async function main() {
  const username = String(process.env.INIT_ADMIN_USERNAME || "").trim();
  const password = String(process.env.INIT_ADMIN_PASSWORD || "").trim();
  if (!username) {
    throw new Error("INIT_ADMIN_USERNAME is required");
  }

  const existing = await prisma.admin.findUnique({ where: { username } });
  if (existing) {
    // Do not rotate/reset credentials on each start.
    return;
  }

  if (!password) {
    throw new Error("INIT_ADMIN_PASSWORD is required for initial bootstrap");
  }
  const passwordHash = await bcrypt.hash(password, 10);

  await prisma.admin.create({
    data: {
      username,
      passwordHash,
      isActive: true,
      fullName: "Администратор",
      email: process.env.INIT_ADMIN_EMAIL?.trim() || null,
      inviteToken: null,
      inviteExpiresAt: null,
    },
  });
}

main()
  .catch((error) => {
    console.error("Seed failed:", error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
