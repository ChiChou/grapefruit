CREATE TABLE `jni` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`type` text NOT NULL,
	`method` text NOT NULL,
	`call_type` text NOT NULL,
	`thread_id` integer,
	`args` text,
	`ret` text,
	`backtrace` text,
	`library` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_jni_device_identifier` ON `jni` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_jni_method` ON `jni` (`method`);--> statement-breakpoint
CREATE INDEX `idx_jni_timestamp` ON `jni` (`timestamp`);