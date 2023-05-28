import { Inject, MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { HashingService } from './hashing/hashing.service';
import { BcryptService } from './hashing/bcrypt.service';
import { AuthenticationController } from './authentication/authentication.controller';
import { AuthenticationService } from './authentication/authentication.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import jwtConfig from './config/jwt.config';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { AccessTokenGuard } from './authentication/guards/access-token/access-token.guard';
import { AuthenticationGuard } from './authentication/guards/authentication/authentication.guard';
import { RefreshTokenIdsStorage } from './authentication/refresh-token-ids.storage/refresh-token-ids.storage';
import { PermissionsGuard } from './authorization/guards/permissions.guard';
import { PolicyHandlerStorage } from './authorization/policies/policy-handlers.storage';
import { FrameworkContributorPolicyHandler } from './authorization/policies/framework-contributor.policy';
import { PoliciesGuard } from './authorization/guards/policies.guard';
import { ApiKeysService } from './authentication/api-keys.service';
import { ApiKey } from 'src/users/api-keys/entities/api-key.entity';
import { ApiKeyGuard } from './authentication/guards/api-key/api-key.guard';
import { GoogleAuthenticationService } from './authentication/social/google-authentication.service';
import { GoogleAuthenticationController } from './authentication/social/google-authentication.controller';
import { OtpAuthenticationService } from './authentication/otp-authentication.service';
import { UserSerializer } from './authentication/serializers/user-serializer/user-serializer';
import createRedisStore from 'connect-redis';
import * as session from 'express-session';
import * as passport from 'passport';
import { Redis } from 'ioredis';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, ApiKey]),
    JwtModule.registerAsync(jwtConfig.asProvider()), // this method converts factory to match asyncModule configuration object
    ConfigModule.forFeature(jwtConfig),
  ], // make User repository available to the module
  // providers: [HashingService, BcryptService], // hashing service is abstract class, cant register is a provider
  providers: [
    {
      provide: HashingService, // will serve as an abstract interface
      useClass: BcryptService, // concrete implementation of the service
    },
    {
      // protect all endpoints with access token guard by default
      provide: APP_GUARD,
      useClass: AuthenticationGuard,
    },
    {
      provide: APP_GUARD,
      useClass: PoliciesGuard, // RolesGuard , PermissionsGuard
    },
    RefreshTokenIdsStorage,
    AccessTokenGuard,
    ApiKeyGuard,
    AuthenticationService,
    PolicyHandlerStorage,
    FrameworkContributorPolicyHandler,
    ApiKeysService,
    GoogleAuthenticationService,
    OtpAuthenticationService,
    UserSerializer,
  ],
  controllers: [AuthenticationController, GoogleAuthenticationController],
})

// TODO https://dev.to/nestjs/setting-up-sessions-with-nestjs-passport-and-redis-210
export class IamModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // const RedisStore = createRedisStore(session);
    let redisClient = createClient();
    redisClient.connect().catch(console.error);
    consumer
      .apply(
        session({
          store: new RedisStore({
            client: new Redis(6379, 'localhost'),
          }),
          secret: process.env.SESSION_SECRET,
          resave: false,
          saveUninitialized: false,
          cookie: {
            sameSite: true,
            httpOnly: true,
          },
        }),
        passport.initialize(),
        passport.session(),
      )
      .forRoutes('*');
  }
}
