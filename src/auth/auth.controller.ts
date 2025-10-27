import { Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signin() {
    return this.authService.signin;
  }

  @Post('signin')
  signup() {
    return this.authService.signup;
  }
}
