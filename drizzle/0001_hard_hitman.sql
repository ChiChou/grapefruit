CREATE TABLE `captured_requests` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`request_id` text NOT NULL,
	`data` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_captured_requests_device_identifier` ON `captured_requests` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_captured_requests_request_id` ON `captured_requests` (`device_id`,`identifier`,`request_id`);
