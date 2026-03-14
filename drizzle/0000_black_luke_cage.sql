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
CREATE INDEX `idx_hbc_created_at` ON `hbc` (`created_at`);--> statement-breakpoint
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
	`backtrace` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP
);
--> statement-breakpoint
CREATE INDEX `idx_hooks_device_identifier` ON `hooks` (`device_id`,`identifier`);--> statement-breakpoint
CREATE INDEX `idx_hooks_timestamp` ON `hooks` (`timestamp`);--> statement-breakpoint
CREATE INDEX `idx_hooks_category` ON `hooks` (`category`);--> statement-breakpoint
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
CREATE UNIQUE INDEX `idx_http_requests_request_id` ON `http_requests` (`device_id`,`identifier`,`request_id`);--> statement-breakpoint
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
--> statement-breakpoint
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
CREATE INDEX `idx_privacy_severity` ON `privacy` (`severity`);--> statement-breakpoint
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