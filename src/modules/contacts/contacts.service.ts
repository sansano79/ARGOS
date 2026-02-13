import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class ContactsService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll() {
        return this.prisma.itContact.findMany({
            where: { isActive: true },
            orderBy: { name: 'asc' },
        });
    }

    async findOne(id: number) {
        const contact = await this.prisma.itContact.findUnique({ where: { id } });
        if (!contact) throw new NotFoundException('Contact not found');
        return contact;
    }

    async create(data: {
        name: string;
        email: string;
        contactPerson?: string;
        department?: string;
        phone?: string;
        products?: string[];
        notes?: string;
    }) {
        return this.prisma.itContact.create({
            data: {
                name: data.name,
                email: data.email,
                contactPerson: data.contactPerson,
                department: data.department,
                phone: data.phone,
                products: JSON.stringify(data.products || []),
                notes: data.notes,
            },
        });
    }

    async update(id: number, data: {
        name?: string;
        email?: string;
        contactPerson?: string;
        department?: string;
        phone?: string;
        products?: string[];
        notes?: string;
    }) {
        await this.findOne(id);
        const updateData: any = { ...data };
        if (data.products) {
            updateData.products = JSON.stringify(data.products);
        }
        return this.prisma.itContact.update({
            where: { id },
            data: updateData,
        });
    }

    async remove(id: number) {
        await this.findOne(id);
        return this.prisma.itContact.update({
            where: { id },
            data: { isActive: false },
        });
    }
}
