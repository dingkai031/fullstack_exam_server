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
		origin: ['http://localhost:3001'],
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
			error: error.details.map((err) => err.message),
		});
	}
	const { email, password } = value;
	const [[user]] = await pool.query(
		`SELECT full_name, email, password FROM users WHERE email=?`,
		[email],
	);
	if (!user)
		return res.status(404).json({ message: 'email or password is invalid' });
	const passwordCompareResult = await bcrypt.compare(password, user.password);
	if (!passwordCompareResult)
		return res.status(404).json({ message: 'email or password is invalid' });
	const { full_name: userName, email: userEmail } = user;
	const token = jwt.sign(
		{ full_name: userName, email: userEmail },
		process.env.WEB_SECRET,
		{ expiresIn: 60 * 30 },
	);

	return res.cookie('access_token', token).json({ message: 'login success' });
});

// app.get('/logout', (req, res) => {});

app.get('/', isAuth, async (req, res) => {
	// const data = await getData('SELECT * FROM users');
	return res.status(200).json(res.locals);
});

// if request url is not valid
app.use((req, res) => {
	return res.status(404).send('error');
});

const port = process.env.PORT || 3001;

app.listen(port, () => {
	console.log(`listening on port ${port}`);
});
