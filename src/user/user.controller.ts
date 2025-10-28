import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import type { Request } from 'express';

@Controller('users')
export class UserController {
  // GET/users/me
  @UseGuards(AuthGuard('jwt'))
  @Get('me')
  get(@Req() req: Request) {
    return req.user;
  }
}
