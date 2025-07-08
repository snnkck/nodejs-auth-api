-- AlterTable
ALTER TABLE "users" ADD COLUMN     "emailVerificationToken" TEXT,
ADD COLUMN     "emailVerificationTokenExpiry" TIMESTAMP(3),
ADD COLUMN     "emailVerified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "resetToken" TEXT,
ADD COLUMN     "resetTokenExpry" TIMESTAMP(3);
