CREATE TABLE `flutter` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`type` text NOT NULL,
	`direction` text NOT NULL,
	`channel` text NOT NULL,
	`data` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_flutter_device_identifier` ON `flutter` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_flutter_timestamp` ON `flutter` (`timestamp`);