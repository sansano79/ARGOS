import {
    Controller, Get, Post, Put, Delete,
    Body, Param, UseGuards, ParseIntPipe,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../auth/decorators/roles.decorator';
import { TagsService } from './tags.service';

@ApiTags('Tags')
@ApiBearerAuth()
@Controller('tags')
@UseGuards(JwtAuthGuard)
export class TagsController {
    constructor(private readonly tagsService: TagsService) { }

    @Get()
    async findAll() {
        return this.tagsService.findAll();
    }

    @Post()
    @UseGuards(RolesGuard)
    @Roles('ADMIN')
    async create(@Body() body: any) {
        return this.tagsService.create(body);
    }

    @Put(':id')
    @UseGuards(RolesGuard)
    @Roles('ADMIN')
    async update(
        @Param('id', ParseIntPipe) id: number,
        @Body() body: any,
    ) {
        return this.tagsService.update(id, body);
    }

    @Delete(':id')
    @UseGuards(RolesGuard)
    @Roles('ADMIN')
    async remove(@Param('id', ParseIntPipe) id: number) {
        return this.tagsService.remove(id);
    }
}
