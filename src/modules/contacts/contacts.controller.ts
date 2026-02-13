import {
    Controller, Get, Post, Put, Delete,
    Body, Param, UseGuards, ParseIntPipe,
} from '@nestjs/common';
import { ApiTags, ApiBearerAuth } from '@nestjs/swagger';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { ContactsService } from './contacts.service';

@ApiTags('Contacts')
@ApiBearerAuth()
@Controller('contacts')
@UseGuards(JwtAuthGuard)
export class ContactsController {
    constructor(private readonly contactsService: ContactsService) { }

    @Get()
    async findAll() {
        const contacts = await this.contactsService.findAll();
        return contacts.map(c => ({
            ...c,
            products: this.parseJson(c.products),
        }));
    }

    @Get(':id')
    async findOne(@Param('id', ParseIntPipe) id: number) {
        const contact = await this.contactsService.findOne(id);
        return {
            ...contact,
            products: this.parseJson(contact.products),
        };
    }

    @Post()
    async create(@Body() body: any) {
        return this.contactsService.create(body);
    }

    @Put(':id')
    async update(
        @Param('id', ParseIntPipe) id: number,
        @Body() body: any,
    ) {
        return this.contactsService.update(id, body);
    }

    @Delete(':id')
    async remove(@Param('id', ParseIntPipe) id: number) {
        return this.contactsService.remove(id);
    }

    private parseJson(value: any): any {
        if (typeof value === 'string') {
            try { return JSON.parse(value); } catch { return value; }
        }
        return value;
    }
}
