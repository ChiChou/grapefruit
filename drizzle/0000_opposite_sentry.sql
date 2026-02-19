CREATE TABLE `crypto` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`symbol` text NOT NULL,
	`direction` text NOT NULL,
	`line` text,
	`extra` text,
	`backtrace` text,
	`data` blob,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_crypto_device_identifier` ON `crypto` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_crypto_timestamp` ON `crypto` (`timestamp`);--> statement-breakpoint
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
CREATE INDEX `idx_flutter_timestamp` ON `flutter` (`timestamp`);--> statement-breakpoint
CREATE TABLE `hooks` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`device_id` text NOT NULL,
	`identifier` text NOT NULL,
	`timestamp` text NOT NULL,
	`category` text NOT NULL,
	`symbol` text NOT NULL,
	`direction` text NOT NULL,
	`line` text,
	`extra` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_hooks_device_identifier` ON `hooks` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_hooks_timestamp` ON `hooks` (`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_hooks_category` ON `hooks` (`category`);--> statement-breakpoint
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
CREATE INDEX `idx_jni_timestamp` ON `jni` (`timestamp`);--> statement-breakpoint
CREATE TABLE `nsurl_requests` (
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
CREATE INDEX `idx_nsurl_requests_device_identifier` ON `nsurl_requests` (`device_id`,`identifier`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_nsurl_requests_request_id` ON `nsurl_requests` (`device_id`,`identifier`,`request_id`);--> statement-breakpoint
CREATE TABLE `preferences` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text
);
