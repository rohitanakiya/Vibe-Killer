// NestJS. The path a route is served at is the controller's prefix joined with
// the method decorator's argument, so reading the decorator alone gives a path
// the server does not serve -- the same shape of mistake Django's include()
// produced before the URLconf tree was walked.
import { Controller, Delete, Get, Post, UseGuards } from '@nestjs/common';

import { AuthGuard } from './auth.guard';

@Controller('nest/invoices')
export class InvoicesController {
  @Get()
  findAll() {
    return [];
  }

  @Get(':id')
  findOne() {
    return {};
  }

  @Post()
  @UseGuards(AuthGuard)
  create() {
    return { ok: true };
  }

  @Delete(':id')
  @UseGuards(AuthGuard)
  remove() {
    return { ok: true };
  }
}
