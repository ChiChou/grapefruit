CREATE TABLE IF NOT EXISTS `hooks` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`category` text NOT NULL,
	`symbol` text NOT NULL,
	`direction` text NOT NULL,
	`payload` text NOT NULL,
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
