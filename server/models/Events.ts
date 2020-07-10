import { Entity, PrimaryGeneratedColumn, Column } from "typeorm";

@Entity()
export class Events {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ length: 32 })
  subject: string;

  @Column({ length: 32 })
  event: string;

  @Column()
  date: Date;

  @Column()
  payload: string;

}
