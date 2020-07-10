import { Entity, PrimaryGeneratedColumn, ManyToOne, Column } from 'typeorm'
import { Tag } from './Tag';

@Entity()
export class Snippet {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @ManyToOne(type => Tag)
  tag: Tag;

  @Column()
  source: string;
}
