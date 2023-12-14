import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { pool } from '../connection.mjs';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';

const router = Router();

router.post('/', async (req, res) => {
	const userSchema = Joi.object({
		full_name: Joi.string().min(8).max(50).required(),
		email: Joi.string().email().max(50).required(),
		password: Joi.string()
			.min(8)
			.custom((value, helpers) => {
				const patterns = [
					{
						regex: /^(?=.*[a-z])/,
						message: 'Password needs at least one lower character',
					},
					{
						regex: /^(?=.*[A-Z])/,
						message: 'Password needs at least one upper character',
					},
					{
						regex: /^(?=.*[0-9])/,
						message: 'Password needs at least one digit character',
					},
					{
						regex: /^(?=.*[!@#$%^&*()_+{}|:"<>?])/,
						message: 'Password needs at least one special character',
					},
				];

				const errors = [];
				for (const pattern of patterns) {
					if (!pattern.regex.test(value)) {
						errors.push(pattern.message);
					}
				}
				if (errors.length > 0) {
					return helpers.message({ custom: errors[0] });
				}
				return value;
			})
			.messages({
				'any.custom':
					'Invalid password. See error details for specific requirements.',
			})
			.required(),
	});
	let value = null;
	try {
		value = await userSchema.validateAsync(req.body);
	} catch (error) {
		return res.status(400).json({
			error: error.details.map((err) => err.message),
		});
	}
	const { full_name, email, password } = value;
	const hashedPassword = await bcrypt.hash(password, 8);
	const id = uuidv4();

	const [createdUser] = await pool.query(
		`INSERT INTO users (id, full_name, email, password) VALUES ('${id}', ?, ?, '${hashedPassword}')`,
		[full_name, email],
	);

	return res.json({ status: 'success', body: createdUser });
});

export default router;
