import { SignInDto } from './dto/sign-in.dto';
import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import { HashingService } from '../hashing/hashing.service';
import { SignUpDto } from './dto/sign-up.dto';
import { JwtService } from '@nestjs/jwt';
import { ConfigType } from '@nestjs/config';
import jwtConfig from '../config/jwt.config';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import {
  InvalidateRefreshTokenError,
  RefreshTokenIdsStorage,
} from './refresh-token-ids.storage/refresh-token-ids.storage';
import { randomUUID } from 'crypto';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User) private readonly usersRepository: Repository<User>,
    private readonly hashingService: HashingService,
    private readonly jwtService: JwtService,
    @Inject(jwtConfig.KEY) // allows to grab jwt config key values and use here
    private readonly jwtConfiguration: ConfigType<typeof jwtConfig>,
    private readonly refreshTokenIdsStorage: RefreshTokenIdsStorage,
  ) {}

  async signUp(signUpDto: SignUpDto) {
    try {
      const user = new User();
      user.email = signUpDto.email;
      user.password = await this.hashingService.hash(signUpDto.password);

      await this.usersRepository.save(user);
    } catch (error) {
      const pgUniqueViolationCode = '23505';

      if (error.code === pgUniqueViolationCode) {
        throw new ConflictException();
      }
      throw error;
    }
  }

  async signIn(SignInDto: SignInDto) {
    const user = await this.usersRepository.findOneBy({
      email: SignInDto.email,
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isEqual = await this.hashingService.compare(
      SignInDto.password,
      user.password,
    );

    if (!isEqual) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return await this.generateTokens(user);
  }

  async generateTokens(user: User) {
    const refreshTokenId = randomUUID();
    const [accessToken, refreshToken] = await Promise.all([
      this.signToken<Partial<ActiveUserData>>(
        user.id,
        this.jwtConfiguration.accessTokenTtl,
        {
          email: user.email,
        },
      ),
      this.signToken(user.id, this.jwtConfiguration.refreshTokenTtl, {
        refreshTokenId,
      }),
    ]);
    // add refresh token id to storage
    await this.refreshTokenIdsStorage.insert(user.id, refreshTokenId);
    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshTokens(refreshTokenDto: RefreshTokenDto) {
    try {
      const { sub, refreshTokenId } = await this.jwtService.verifyAsync<
        Pick<ActiveUserData, 'sub'> & { refreshTokenId: string }
      >(refreshTokenDto.refreshToken, {
        secret: this.jwtConfiguration.secret,
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
      });

      const user = await this.usersRepository.findOneOrFail({
        where: {
          id: sub,
        },
      });
      // validate token id
      const isValid = await this.refreshTokenIdsStorage.validate(
        user.id,
        refreshTokenId,
      );

      // invalidate token id so it cant be used with any subsequent requests. //!refresh token rotation
      if (isValid) {
        await this.refreshTokenIdsStorage.invalidate(user.id);
      } else {
        throw new Error('Refresh token is invalid');
      }

      return await this.generateTokens(user);
    } catch (error) {
      if (error instanceof InvalidateRefreshTokenError) {
        throw new UnauthorizedException('Access Denied');
      }
      throw new UnauthorizedException('Invalid credentials');
    }
  }

  private async signToken<T>(userId: number, expiresIn: number, payload?: T) {
    return await this.jwtService.signAsync(
      // generates a new JWT access token
      {
        // payload
        sub: userId,
        ...payload,
      },
      {
        // jwt configuration
        audience: this.jwtConfiguration.audience,
        issuer: this.jwtConfiguration.issuer,
        secret: this.jwtConfiguration.secret,
        expiresIn: this.jwtConfiguration.accessTokenTtl,
      },
    );
  }
}
