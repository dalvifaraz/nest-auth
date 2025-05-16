import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Hello World! - Test Develop Branch';
  }

  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User> 
  ) {

  }

  async create(data: any): Promise<User>{
    return this.userRepository.save(data);
  }

  async findOne(email: any): Promise<User | null> {
    return this.userRepository.findOne({ where: { email }});
  }

  async findOneById(id: number): Promise<User | null> {
    return this.userRepository.findOne({ where: { id }});
  }
}
 