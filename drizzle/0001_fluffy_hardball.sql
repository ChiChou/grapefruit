ALTER TABLE `crypto` ADD `category` text;--> statement-breakpoint
CREATE INDEX `idx_crypto_category` ON `crypto` (`category`);