import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import * as bcrypt from 'bcrypt';

@Injectable()
export class UsersService {
    constructor(private readonly prisma: PrismaService) { }

    async findAll() {
        return this.prisma.user.findMany({
            orderBy: { createdAt: 'desc' },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                isActive: true,
                lastLoginAt: true,
                createdAt: true,
                updatedAt: true,
            },
        });
    }

    async findOne(id: number) {
        const user = await this.prisma.user.findUnique({
            where: { id },
            select: {
                id: true,
                email: true,
                name: true,
                role: true,
                isActive: true,
                lastLoginAt: true,
                createdAt: true,
                updatedAt: true,
            },
        });
        if (!user) throw new NotFoundException('User not found');
        return user;
    }

    async create(data: {
        email: string;
        password: string;
        name: string;
        role?: string;
    }) {
        const existing = await this.prisma.user.findUnique({
            where: { email: data.email },
        });
        if (existing) throw new ConflictException('Email already in use');

        const passwordHash = await bcrypt.hash(data.password, 12);
        const user = await this.prisma.user.create({
            data: {
                email: data.email,
                passwordHash,
                name: data.name,
                role: data.role || 'USER',
            },
        });

        const { passwordHash: _, ...result } = user;
        return result;
    }

    async update(id: number, data: {
        email?: string;
        name?: string;
        role?: string;
        password?: string;
        isActive?: boolean;
    }) {
        await this.findOne(id);
        const updateData: any = {};
        if (data.email) updateData.email = data.email;
        if (data.name) updateData.name = data.name;
        if (data.role) updateData.role = data.role;
        if (data.isActive !== undefined) updateData.isActive = data.isActive;
        if (data.password) {
            updateData.passwordHash = await bcrypt.hash(data.password, 12);
        }

        const user = await this.prisma.user.update({
            where: { id },
            data: updateData,
        });

        const { passwordHash: _, ...result } = user;
        return result;
    }

    async remove(id: number) {
        await this.findOne(id);
        return this.prisma.user.update({
            where: { id },
            data: { isActive: false },
        });
    }
}
