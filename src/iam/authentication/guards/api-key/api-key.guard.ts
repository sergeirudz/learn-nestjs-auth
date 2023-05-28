import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { ApiKeysService } from '../../api-keys.service';
import { ApiKey } from 'src/users/api-keys/entities/api-key.entity';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Request } from 'express';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';
import { REQUEST_USER_KEY } from 'src/iam/iam.constants';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly apiKeyService: ApiKeysService,
    @InjectRepository(ApiKey)
    private readonly apiKeyRepository: Repository<ApiKey>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();

    const apiKey = this.extractApiKeyFromHeader(request);
    if (!apiKey) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const apiKeyEntityId = this.apiKeyService.extractIdFromApiKey(apiKey);

    try {
      // retrieve the api key from the database
      const apiKeyEntity = await this.apiKeyRepository.findOne({
        where: { uuid: apiKeyEntityId },
        relations: { user: true },
      });

      // validate the API key and compare it with its hashed version in the db
      await this.apiKeyService.validate(apiKey, apiKeyEntity.key);

      // assign user entity to the request object so it can be retrieved in the controller methods
      request[REQUEST_USER_KEY] = {
        sub: apiKeyEntity.user.id,
        email: apiKeyEntity.user.email,
        role: apiKeyEntity.user.role,
        permissions: apiKeyEntity.user.permissions,
      } as ActiveUserData;
    } catch (error) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return true;
  }

  private extractApiKeyFromHeader(request: Request): string | undefined {
    const [type, key] = request.headers.authorization?.split(' ') ?? [];
    return type === 'ApiKey' ? key : undefined;
  }
}
