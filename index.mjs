import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { config } from 'dotenv';
import helmet from 'helmet';
import Joi from 'joi';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { pool } from './connection.mjs';
import cookieParser from 'cookie-parser';
import { v4 as uuidv4 } from 'uuid';

import { OAuth2Client } from 'google-auth-library';

// import sendEmail from './utils/sendEmail.mjs';
config();

// routes import
import UserRoutes from './routes/UserRoutes.mjs';

// middleware import
import isAuth from './middleware/isAuth.mjs';

// express configuration
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(helmet());
// const corsOption = {
// 	origin: [
// 		'http://localhost:5173',
// 		'https://fullstack-exam-client.codewithyovan.tech',
// 		'https://fullstack-exam-client.codewithyovan.tech/',
// 		'*',
// 	],
// 	credentials: true,
// };
app.use(cors());

// routes registration
app.use('/user', UserRoutes);

app.post('/login', async (req, res) => {
	const loginSchema = Joi.object({
		email: Joi.string().required(),
		password: Joi.string().required(),
	});
	let value = null;
	try {
		value = await loginSchema.validateAsync(req.body);
	} catch (error) {
		return res.status(400).json({
			message: error.details[0].message,
		});
	}
	const { email, password } = value;
	const [[user]] = await pool.query(
		`SELECT full_name, email, password, total_login, status FROM users WHERE email=?`,
		[email],
	);
	if (!user)
		return res.status(404).json({ message: 'email or password is invalid' });
	if (parseInt(user.status) === 0)
		return res.status(401).json({
			message: 'email is not verified',
			status: 'unverified_email',
		});
	const passwordCompareResult = await bcrypt.compare(password, user.password);
	if (!passwordCompareResult)
		return res.status(404).json({ message: 'email or password is invalid' });
	const {
		full_name: userName,
		email: userEmail,
		total_login: currentTotalLogin,
	} = user;
	const token = jwt.sign(
		{ full_name: userName, email: userEmail },
		process.env.WEB_SECRET,
		{ expiresIn: 60 * 60 * 12 },
	);
	const updatedTotalLogin = parseInt(currentTotalLogin) + 1;
	await pool.query(
		'UPDATE users SET total_login=?, last_login_date=CURRENT_TIMESTAMP WHERE email=?',
		[updatedTotalLogin, email],
	);

	return res.json({ message: 'login success', token });
	//somehow cookie doesnt set automatically in the react app
	// .cookie('access_token', token, { sameSite: 'none' })
});

app.post('/login-oauth', async (req, res) => {
	let email = null;
	let full_name = null;
	let exp = null;
	if (req.body.type === 'google') {
		const client = new OAuth2Client();
		let ticket = null;
		try {
			ticket = await client.verifyIdToken({
				idToken: req.body.credential,
				audience: req.body.clientId,
			});
		} catch (e) {
			return res.status(400).json({ message: 'failed to verify token' });
		}
		const payload = ticket.getPayload();
		email = payload.email;
		full_name = payload.name;
		exp = payload.exp;
	} else if (req.body.type === 'facebook') {
		email = req.body.email;
		full_name = req.body.full_name;
	} else {
		return res.status(404).json({ message: 'uknown request' });
	}
	// check if the user has registered or not
	const [[userData]] = await pool.query(
		'SELECT email FROM users WHERE email=?',
		[email],
	);
	// if not register the user without password
	let result = null;
	if (!userData) {
		const id = uuidv4();
		await pool.query(
			'INSERT INTO users (id, email, full_name, status, password, last_login_date, total_login) VALUES (?, ?, ?, "1", "", CURRENT_TIMESTAMP, "1")',
			[id, email, full_name],
		);
	} else {
		result = await pool.query(
			'UPDATE users SET last_login_date=CURRENT_TIMESTAMP, total_login=total_login + 1 WHERE email=?',
			[email],
		);
	}
	const token = jwt.sign(
		{
			full_name,
			email,
			exp: exp ? exp : Math.floor(new Date().getTime() / 1000) + 60 * 60 * 12,
		},
		process.env.WEB_SECRET,
	);

	return res.json({ message: 'login success', token });
});

app.get('/logout', isAuth, async (req, res) => {
	const { email: userEmail } = res.locals.userData;
	await pool.query(
		'UPDATE users SET last_logout_date=CURRENT_TIMESTAMP WHERE email=?',
		[userEmail],
	);
	return res
		.clearCookie('access_token')
		.status(200)
		.json({ message: 'logout success' });
});

// if request url is not valid
app.use((req, res) => {
	return res.status(404).send('error');
});

const port = process.env.PORT || 3001;

app.listen(port, () => {
	console.log(`listening on port ${port}`);
});
