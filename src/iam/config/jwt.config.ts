import { registerAs } from '@nestjs/config';

const jwtConfig = registerAs('jwt', () => {
  return {
    secret: process.env.JWT_SECRET,
    audience: `${process.env.JWT_AUDIENCE}` as string,
    issuer: `${process.env.JWT_ISSUER}`,
    accessTokenTtl: parseInt(process.env.JWT_ACCESS_TOKEN_TTL ?? '3600', 10),
    refreshTokenTtl: parseInt(process.env.JWT_REFRESH_TOKEN_TTL ?? '86400', 10),
  };
});

export default jwtConfig;
