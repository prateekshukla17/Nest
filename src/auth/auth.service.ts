import { Body, ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import type { AuthDto } from './dto';
import * as argon from 'argon2'; //use for password hashing
import { PrismaClient } from 'generated/prisma/client';
import { PrismaClientKnownRequestError } from 'generated/prisma/internal/prismaNamespace';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
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

      return this.signToken(user.id, user.hash);
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
    try {
      const user = await this.prisma.users.findUnique({
        where: {
          email: dto.email,
        },
      });
      if (!user) throw new ForbiddenException('No user Found incorrect');
      const pwmatch = await argon.verify(user.hash, dto.password);
      if (!pwmatch) throw new ForbiddenException('Credentials incorrect');
      return user;
    } catch (err) {
      console.error(err);
    }
  }

  async signToken(userID: Number, email: String): Promise<{ token }> {
    const payload = {
      sub: userID,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const token = this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return {
      token: token,
    };
  }
}
