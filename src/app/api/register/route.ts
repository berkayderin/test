import { NextResponse } from 'next/server'
import User from '@/models/User'
import bcrypt from 'bcryptjs'
import connect from '@/utils/db'

export const POST = async (request: any) => {
	const { email, password } = await request.json()

	await connect()

	const existingUser = await User.findOne({ email })

	if (existingUser) {
		return new NextResponse('E-posta zaten kullanımda.', { status: 400 })
	}

	const hashedPassword = await bcrypt.hash(password, 5)
	const newUser = new User({
		email,
		password: hashedPassword
	})

	try {
		await newUser.save()
		return new NextResponse('Kullanıcı kayıtlı.', { status: 200 })
	} catch (err: any) {
		return new NextResponse(err, {
			status: 500
		})
	}
}
