import { ExecutionContext, createParamDecorator } from '@nestjs/common';
import { REQUEST_USER_KEY } from '../iam.constants';
import { ActiveUserData } from '../interfaces/active-user-data.interface';

export const ActiveUser = createParamDecorator(
  (field: keyof ActiveUserData | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest(); // get request object
    const user: ActiveUserData = request[REQUEST_USER_KEY]; // get decoded user payload

    return field ? user?.[field] : user; // if field passed, grab the field from user payload
  },
);
