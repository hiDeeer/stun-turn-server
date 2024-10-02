// src/turn/turn.module.ts
import { Module } from '@nestjs/common';
import { TurnService } from './turn.service';

@Module({
  providers: [TurnService],
})
export class TurnModule {}
