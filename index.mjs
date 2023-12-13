import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import { config } from 'dotenv';
import helmet from 'helmet';
import { getData } from './connection.mjs';
config();

// routes import
import UserRoutes from './routes/UserRoutes.mjs';

// express configuration
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(helmet());
app.use(
	cors({
		origin: ['http://localhost:3001'],
	}),
);

// routes registration
app.use('/user', UserRoutes);

const port = process.env.PORT || 3001;

app.get('/', async (req, res) => {
	// const data = await getData('SELECT * FROM users');
	return res.status(200).json({ test: req.body });
});

// if request url is not valid
app.use((req, res) => {
	return res.status(404).send('error');
});

app.listen(port, () => {
	console.log(`listening on port ${port}`);
});
