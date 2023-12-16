import { Router } from 'express';
import bcrypt from 'bcryptjs';
import { pool } from '../connection.mjs';
import { v4 as uuidv4 } from 'uuid';
import Joi from 'joi';
import sendEmail from '../utils/sendEmail.mjs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { config } from 'dotenv';
import jwt from 'jsonwebtoken';

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
router.get('/:emailUser', isAuth, async (req, res) => {
	const { emailUser } = req.params;
	const [[userData]] = await pool.query(
		'SELECT full_name, email FROM users WHERE email=?',
		[emailUser],
	);

	if (!userData)
		return res
			.clearCookie('access_token')
			.status(404)
			.json({ message: 'unknown user' });
	return res.json({
		message: 'success',
		body: {
			full_name: userData.full_name,
			email: userData.email,
		},
	});
});
router.get('/verify-email/:emailId', async (req, res) => {
	const { emailId } = req.params;
	const [[emailData]] = await pool.query(
		'SELECT * FROM email_verification WHERE id=?',
		[emailId],
	);
	if (!emailData)
		return res
			.status(404)
			.json({ message: 'Account is activated or invalid', status: 'invalid' });
	const { user_id: userId } = emailData;
	await pool.query("UPDATE users SET status='1' WHERE id=?", [userId]);
	await pool.query('DELETE FROM email_verification WHERE id=?', [emailId]);
	const [[{ full_name, email, total_login }]] = await pool.query(
		'SELECT full_name, email, total_login FROM users WHERE id=?',
		[userId],
	);
	const signedData = { full_name, email, total_login };
	const token = jwt.sign(signedData, process.env.WEB_SECRET, {
		expiresIn: 60 * 60 * 12,
	});
	return res.json({
		message: 'email verified',
		status: 'success',
		token,
	});
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
	const [[finduser]] = await pool.query(
		`SELECT email FROM users WHERE email=?`,
		[email],
	);
	if (finduser)
		return res.status(400).json({ message: 'email already registered' });
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
		`${process.env.CLIENT_URL}/verify-email/${emailVerifId}`,
	);

	return res.json({
		status: 'success',
		body: { createdUser, createdEmailVerif },
		emailStatus: sendEmailStatus,
	});
});
router.patch('/', isAuth, async (req, res) => {
	const {
		full_name: newFull_name,
		'old-password': oldPassword,
		password: newPassword,
	} = req.body;
	const { email: authEmail } = res.locals.userData;

	const columnNames = [];
	const tableValues = [];
	const messages = [];
	const newChangedData = {};
	if (newFull_name) {
		columnNames.push('full_name');
		tableValues.push(newFull_name);
		messages.push('full name changed');
		newChangedData['full_name'] = newFull_name;
	}
	if (oldPassword && newPassword) {
		const [[userPassword]] = await pool.query(
			'SELECT password FROM users WHERE email=?',
			[authEmail],
		);
		const passwordCompareResult = await bcrypt.compare(
			oldPassword,
			userPassword.password,
		);
		if (!passwordCompareResult)
			return res.status(404).json({ message: 'Invalid old passowrd' });
		let validatePassword = null;
		try {
			validatePassword = Joi.string()
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
				.required()
				.validate(newPassword);
		} catch (error) {
			return res.status(400).json({
				error: error.details.map((err) => err.message),
			});
		}
		const hashedPassword = await bcrypt.hash(validatePassword.value, 8);

		columnNames.push('password');
		tableValues.push(hashedPassword);
		messages.push('password changed');
	}
	const modifiedColumns = columnNames.map((col) => col + '=?');
	tableValues.push(authEmail);

	await pool.query(
		`UPDATE users SET ${modifiedColumns.join(', ')} WHERE email=?`,
		tableValues,
	);

	return res.json({
		message: messages,
		body: newChangedData,
	});
});

export default router;
