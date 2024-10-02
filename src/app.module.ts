// src/app.module.ts
import { Module } from '@nestjs/common';
import { TurnModule } from './turn/turn.module';

@Module({
  imports: [TurnModule],
})
export class AppModule {}
