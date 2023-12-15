import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { pool } from '../connection.mjs';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';
import sendEmail from '../utils/sendEmail.mjs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { config } from 'dotenv';

import isAuth from '../middleware/isAuth.mjs';

const __fileDirectory = fileURLToPath(import.meta.url);
const __dirDirectory = dirname(__fileDirectory);
config({ path: `${__dirDirectory}/../.env` });

const router = Router();

router.get('/', isAuth, async (req, res) => {
	const [allUser] = await pool.query(
		'SELECT id, created_at, full_name, email, total_login, last_logout_date, last_login_date FROM users',
	);
	res.json(allUser);
});
router.get('/verify-email/:emailId', async (req, res) => {
	const { emailId } = req.params;
	const [[emailData]] = await pool.query(
		'SELECT * FROM email_verification WHERE id=?',
		[emailId],
	);
	if (!emailData)
		return res.status(404).json({ mesage: 'Account is activated or invalid' });
	const { user_id: userId } = emailData;
	await pool.query("UPDATE users SET status='1' WHERE id=?", [userId]);
	await pool.query('DELETE FROM email_verification WHERE id=?', [emailId]);
	return res.json({ message: 'email verified' });
});

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

	const capitalizeName = full_name
		.split(' ')
		.map((word) => word[0].toUpperCase() + word.substr(1))
		.join(' ');

	const emailVerifId = uuidv4();

	const [createdEmailVerif] = await pool.query(
		`INSERT INTO email_verification (id, user_id) VALUES ('${emailVerifId}', '${id}' )`,
	);

	const sendEmailStatus = await sendEmail(
		email,
		capitalizeName,
		`${process.env.BASE_URL}/user/verify-email/${emailVerifId}`,
	);

	return res.json({
		status: 'success',
		body: { createdUser, createdEmailVerif },
		emailStatus: sendEmailStatus,
	});
});

export default router;
