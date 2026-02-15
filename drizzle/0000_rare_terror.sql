CREATE TABLE IF NOT EXISTS `crypto` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`symbol` text NOT NULL,
	`direction` text NOT NULL,
	`line` text,
	`extra` text,
	`backtrace` text,
	`data` blob,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_crypto_device_identifier` ON `crypto` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_crypto_timestamp` ON `crypto` (`timestamp`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `hooks` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`category` text NOT NULL,
	`symbol` text NOT NULL,
	`direction` text NOT NULL,
	`line` text,
	`extra` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_hooks_device_identifier` ON `hooks` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_hooks_timestamp` ON `hooks` (`timestamp`);--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_hooks_category` ON `hooks` (`category`);--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `preferences` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `requests` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`request_id` text NOT NULL,
	`data` text NOT NULL,
	`attachment` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX IF NOT EXISTS `idx_requests_device_identifier` ON `requests` (`device_id`,`identifier`);--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `idx_requests_request_id` ON `requests` (`device_id`,`identifier`,`request_id`);
