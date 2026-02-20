CREATE TABLE `xpc_logs` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`protocol` text NOT NULL,
	`event` text NOT NULL,
	`direction` text NOT NULL,
	`service` text,
	`peer` integer,
	`message` text NOT NULL,
	`backtrace` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_xpc_logs_device_identifier` ON `xpc_logs` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_xpc_logs_timestamp` ON `xpc_logs` (`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_xpc_logs_protocol` ON `xpc_logs` (`protocol`);