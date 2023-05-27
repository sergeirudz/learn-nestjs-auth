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
