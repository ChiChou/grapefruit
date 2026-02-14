CREATE TABLE `crypto_logs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`symbol` text NOT NULL,
	`direction` text NOT NULL,
	`line` text,
	`extra` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_crypto_logs_device_identifier` ON `crypto_logs` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_crypto_logs_timestamp` ON `crypto_logs` (`timestamp`);