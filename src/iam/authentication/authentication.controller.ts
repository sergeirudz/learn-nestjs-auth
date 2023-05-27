import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { SignUpDto } from './dto/sign-up.dto';
import { AuthenticationService } from './authentication.service';
import { SignInDto } from './dto/sign-in.dto';
import { Response } from 'express';
import { AuthType } from '../enums/auth-type.enum';
import { Auth } from './decorators/auth.decorator';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Auth(AuthType.None) // disable authentication guard for this controller
@Controller('authentication')
export class AuthenticationController {
  constructor(private readonly authService: AuthenticationService) {}

  @Post('sign-up')
  async signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @HttpCode(HttpStatus.OK) // successful will be 200
  @Post('sign-in')
  async signIn(
    @Res({ passthrough: true }) response: Response,
    @Body() signInDto: SignInDto,
  ) {
    return this.authService.signIn(signInDto); // send back token
    /* 
!send back token as cookie for more security
const accessToken = await this.authService.signIn(signInDto);
    response.cookie('accessToken', accessToken, {
      secure: true,
      httpOnly: true,
      sameSite: 'none',
    }); */
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh-tokens')
  async refreshTokens(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshTokens(refreshTokenDto);
  }
}
