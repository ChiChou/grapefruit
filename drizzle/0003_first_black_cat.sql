CREATE TABLE `http_requests` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`request_id` text NOT NULL,
	`data` text NOT NULL,
	`attachment` text,
	`mime` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_http_requests_device_identifier` ON `http_requests` (`device_id`,`identifier`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_http_requests_request_id` ON `http_requests` (`device_id`,`identifier`,`request_id`);