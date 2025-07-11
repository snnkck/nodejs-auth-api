-- AlterTable
ALTER TABLE "users" ADD COLUMN     "refreshToken" TEXT,
ADD COLUMN     "refreshTokenExpiry" TIMESTAMP(3);
