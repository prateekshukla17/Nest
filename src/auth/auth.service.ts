import { Body, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import type { AuthDto } from './dto';
import * as argon from 'argon2'; //use for password hashing
import { PrismaClient } from 'generated/prisma/client';
import { PrismaClientKnownRequestError } from 'generated/prisma/internal/prismaNamespace';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(@Body() dto: AuthDto) {
    //Generate a password hash
    const hash = await argon.hash(dto.password);

    try {
      const user = await this.prisma.users.create({
        data: {
          email: dto.email,
          hash: hash,
        },
      });

      return user;
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        if (error.code === 'P2002') {
          throw new ForbiddenException('Creds Already Taken');
        }
      }
      throw error;
    }
  }

  async signin(@Body() dto: AuthDto) {
    //Find the user by email
    const user = await this.prisma.users.findUnique({
      where: {
        email: dto.email,
      },
    });
    if (!user) throw new ForbiddenException('Credentials incorrect');

    //if user does not exist, throw error
    // if exitst: compare passwords
    // if password incorrect: throw error
  }
}
