CREATE TABLE `privacy` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`category` text NOT NULL,
	`severity` text NOT NULL,
	`symbol` text NOT NULL,
	`direction` text NOT NULL,
	`line` text,
	`extra` text,
	`backtrace` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_privacy_device_identifier` ON `privacy` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_privacy_timestamp` ON `privacy` (`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_privacy_category` ON `privacy` (`category`);--> statement-breakpoint
CREATE INDEX `idx_privacy_severity` ON `privacy` (`severity`);