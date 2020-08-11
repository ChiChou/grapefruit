import { Entity, PrimaryGeneratedColumn, Column, ManyToMany, JoinTable } from 'typeorm'
import { Tag } from './Tag';

@Entity()
export class Snippet {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @ManyToMany(type => Tag)
  @JoinTable()
  tags: Tag[];

  @Column()
  source: string;
}
