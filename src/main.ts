import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as session from 'express-session';
import { join } from 'path';
import { NestExpressApplication } from '@nestjs/platform-express';

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.enableCors({
    origin: ['http://localhost:8080', 'http://localhost:3000'],
    credentials: true,
  });

  app.use(
    session({
      secret: 'fndnf9hifekfnkdfndknk',
      resave: false,
      saveUninitialized: false,
    }),
  );

  app.useStaticAssets(join(__dirname, '..', 'public'));
  app.setBaseViewsDir(join(__dirname, '..', 'views'));
  app.setViewEngine('hbs');

  await app.listen(9000);
}
bootstrap();
