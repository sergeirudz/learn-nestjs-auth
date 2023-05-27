import {
  Injectable,
  OnApplicationBootstrap,
  OnApplicationShutdown,
} from '@nestjs/common';
import { Redis } from 'ioredis';

export class InvalidateRefreshTokenError extends Error {}

@Injectable()
export class RefreshTokenIdsStorage
  implements OnApplicationBootstrap, OnApplicationShutdown
{
  private redisClient: Redis; // should be separate module
  onApplicationBootstrap() {
    this.redisClient = new Redis({
      host: 'localhost',
      port: 6379,
    });
  }

  onApplicationShutdown(signal?: string) {
    return this.redisClient.quit();
  }

  // insert new token to redis db
  async insert(userId: number, tokenId: string): Promise<void> {
    await this.redisClient.set(await this.getKey(userId), tokenId);
  }

  // validate the token passed in
  async validate(userId: number, tokenId: string): Promise<boolean> {
    // confirm token received to the one in the db
    const storedId = await this.redisClient.get(await this.getKey(userId));

    if (storedId !== tokenId) {
      throw new InvalidateRefreshTokenError();
    }

    return storedId === tokenId;
  }

  // invalidate token by removing it from redis db
  async invalidate(userId: number): Promise<void> {
    // delete specific entry from the db
    await this.redisClient.del(await this.getKey(userId));
  }

  // constructs the key based on userId
  private getKey(userId: number): string {
    return `user-${userId}`;
  }
}
