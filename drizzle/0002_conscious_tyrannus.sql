CREATE TABLE `hbc` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`url` text NOT NULL,
	`hash` text NOT NULL,
	`size` integer NOT NULL,
	`data` blob NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_hbc_device_identifier` ON `hbc` (`device_id`,`identifier`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_hbc_hash` ON `hbc` (`hash`);--> statement-breakpoint
CREATE INDEX `idx_hbc_created_at` ON `hbc` (`created_at`);