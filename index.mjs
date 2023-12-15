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
app.use(
	cors({
		origin: ['http://localhost:5173'],
		credentials: true,
	}),
);

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
		`SELECT full_name, email, password, total_login FROM users WHERE email=?`,
		[email],
	);
	if (!user)
		return res.status(404).json({ message: 'email or password is invalid' });
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

// app.get('/', async (req, res) => {
// 	// const data = await getData('SELECT * FROM users');
// 	return res.status(200).json(req.cookies);
// });

// app.get('/test-send-email', async (req, res) => {
// 	const result = await sendEmail('yovanjulioadam@gmail.com', 'John cena');
// 	// const data = await getData('SELECT * FROM users');
// 	return res.status(200).json(result);
// });

// if request url is not valid
app.use((req, res) => {
	return res.status(404).send('error');
});

const port = process.env.PORT || 3001;

app.listen(port, () => {
	console.log(`listening on port ${port}`);
});
