ALTER TABLE `captured_requests` ADD `attachment` text;--> statement-breakpoint
DROP INDEX IF EXISTS `idx_captured_requests_request_id`;--> statement-breakpoint
CREATE UNIQUE INDEX `idx_captured_requests_request_id` ON `captured_requests` (`device_id`, `identifier`, `request_id`);
