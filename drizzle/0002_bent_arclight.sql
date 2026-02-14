ALTER TABLE `hooks` ADD `line` text;--> statement-breakpoint
ALTER TABLE `hooks` ADD `extra` text;--> statement-breakpoint
ALTER TABLE `hooks` DROP COLUMN `payload`;
