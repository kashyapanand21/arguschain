-- CreateTable
CREATE TABLE "StoredFile" (
    "tokenId" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "mimeType" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "contentHash" TEXT NOT NULL,
    "storagePath" TEXT NOT NULL,
    "wrappedDek" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- CreateTable
CREATE TABLE "Decision" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "ts" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "identityId" TEXT NOT NULL,
    "tokenId" TEXT,
    "action" TEXT NOT NULL,
    "reasonCode" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL DEFAULT 0,
    "reasons" TEXT NOT NULL DEFAULT '[]',
    "prevHash" TEXT NOT NULL,
    "rowHash" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "StoredFile_contentHash_key" ON "StoredFile"("contentHash");
