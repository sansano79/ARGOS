import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';

@Injectable()
export class TagsService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll() {
        return this.prisma.vulnerabilityTag.findMany({
            orderBy: { name: 'asc' },
        });
    }

    async create(data: { name: string; color?: string }) {
        const existing = await this.prisma.vulnerabilityTag.findUnique({
            where: { name: data.name },
        });
        if (existing) throw new ConflictException('Tag already exists');

        return this.prisma.vulnerabilityTag.create({
            data: {
                name: data.name,
                color: data.color || '#3B6CB5',
            },
        });
    }

    async update(id: number, data: { name?: string; color?: string }) {
        const tag = await this.prisma.vulnerabilityTag.findUnique({ where: { id } });
        if (!tag) throw new NotFoundException('Tag not found');

        return this.prisma.vulnerabilityTag.update({
            where: { id },
            data,
        });
    }

    async remove(id: number) {
        const tag = await this.prisma.vulnerabilityTag.findUnique({ where: { id } });
        if (!tag) throw new NotFoundException('Tag not found');

        return this.prisma.vulnerabilityTag.delete({ where: { id } });
    }
}
