# Info

- Course - Authentication and Authorization
  - https://courses.nestjs.com/

# Commands

nest g service iam/hashing  
nest g service iam/hashing/bcrypt --flat
nest g class iam/authentication/dto/sign-in.dto --no-spec

## Update user role

npm run start -- --entryFile repl
await get("UserRepository").update({ id: 1 }, { role: 'regular' })
await get("UserRepository").update({ id: 1 }, { permissions: ['create_coffee'] })
await get("UserRepository").find()
Create API key:

- uuid = 'random_unique_id'
- payload = await get(ApiKeysService).createAndHash(uuid)
{
  apiKey: 'cmFuZG9tX3VuaXF1ZV9pZC1iMzhkMThiYi1hZmM2LTRkOWEtYmZkMC01MDk4YTViNjcwOWY=',
  hashedKey: '$2b$10$bY6PlYcnkYCbvj620ldwD.Qk.W4OZavMcSuOBRBsES6AmpoZYiYbK'
}
- await get("ApiKeyRepository").save({ uuid, key: payload.hashedKey, user: { id: 1 }})
