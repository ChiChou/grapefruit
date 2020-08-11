import {MigrationInterface, QueryRunner} from "typeorm";

export class initial1597165983060 implements MigrationInterface {
    name = 'initial1597165983060'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`CREATE TABLE "event" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "subject" varchar(32) NOT NULL, "event" varchar(32) NOT NULL, "date" datetime NOT NULL, "payload" varchar NOT NULL)`);
        await queryRunner.query(`CREATE TABLE "tag" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "name" varchar NOT NULL)`);
        await queryRunner.query(`CREATE TABLE "snippet" ("id" integer PRIMARY KEY AUTOINCREMENT NOT NULL, "name" varchar NOT NULL, "source" varchar NOT NULL)`);
        await queryRunner.query(`CREATE TABLE "snippet_tags_tag" ("snippetId" integer NOT NULL, "tagId" integer NOT NULL, PRIMARY KEY ("snippetId", "tagId"))`);
        await queryRunner.query(`CREATE INDEX "IDX_4cc351c82a0b98e06b256b8576" ON "snippet_tags_tag" ("snippetId") `);
        await queryRunner.query(`CREATE INDEX "IDX_3e1456d333910cebbd3b36195c" ON "snippet_tags_tag" ("tagId") `);
        await queryRunner.query(`DROP INDEX "IDX_4cc351c82a0b98e06b256b8576"`);
        await queryRunner.query(`DROP INDEX "IDX_3e1456d333910cebbd3b36195c"`);
        await queryRunner.query(`CREATE TABLE "temporary_snippet_tags_tag" ("snippetId" integer NOT NULL, "tagId" integer NOT NULL, CONSTRAINT "FK_4cc351c82a0b98e06b256b8576e" FOREIGN KEY ("snippetId") REFERENCES "snippet" ("id") ON DELETE CASCADE ON UPDATE NO ACTION, CONSTRAINT "FK_3e1456d333910cebbd3b36195c9" FOREIGN KEY ("tagId") REFERENCES "tag" ("id") ON DELETE CASCADE ON UPDATE NO ACTION, PRIMARY KEY ("snippetId", "tagId"))`);
        await queryRunner.query(`INSERT INTO "temporary_snippet_tags_tag"("snippetId", "tagId") SELECT "snippetId", "tagId" FROM "snippet_tags_tag"`);
        await queryRunner.query(`DROP TABLE "snippet_tags_tag"`);
        await queryRunner.query(`ALTER TABLE "temporary_snippet_tags_tag" RENAME TO "snippet_tags_tag"`);
        await queryRunner.query(`CREATE INDEX "IDX_4cc351c82a0b98e06b256b8576" ON "snippet_tags_tag" ("snippetId") `);
        await queryRunner.query(`CREATE INDEX "IDX_3e1456d333910cebbd3b36195c" ON "snippet_tags_tag" ("tagId") `);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`DROP INDEX "IDX_3e1456d333910cebbd3b36195c"`);
        await queryRunner.query(`DROP INDEX "IDX_4cc351c82a0b98e06b256b8576"`);
        await queryRunner.query(`ALTER TABLE "snippet_tags_tag" RENAME TO "temporary_snippet_tags_tag"`);
        await queryRunner.query(`CREATE TABLE "snippet_tags_tag" ("snippetId" integer NOT NULL, "tagId" integer NOT NULL, PRIMARY KEY ("snippetId", "tagId"))`);
        await queryRunner.query(`INSERT INTO "snippet_tags_tag"("snippetId", "tagId") SELECT "snippetId", "tagId" FROM "temporary_snippet_tags_tag"`);
        await queryRunner.query(`DROP TABLE "temporary_snippet_tags_tag"`);
        await queryRunner.query(`CREATE INDEX "IDX_3e1456d333910cebbd3b36195c" ON "snippet_tags_tag" ("tagId") `);
        await queryRunner.query(`CREATE INDEX "IDX_4cc351c82a0b98e06b256b8576" ON "snippet_tags_tag" ("snippetId") `);
        await queryRunner.query(`DROP INDEX "IDX_3e1456d333910cebbd3b36195c"`);
        await queryRunner.query(`DROP INDEX "IDX_4cc351c82a0b98e06b256b8576"`);
        await queryRunner.query(`DROP TABLE "snippet_tags_tag"`);
        await queryRunner.query(`DROP TABLE "snippet"`);
        await queryRunner.query(`DROP TABLE "tag"`);
        await queryRunner.query(`DROP TABLE "event"`);
    }

}
