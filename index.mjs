import express from 'express';
import bodyParser from 'body-parser';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { config } from 'dotenv';
import helmet from 'helmet';
config();

// express configuration
const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(helmet());
app.use(
	cors({
		origin: ['http://localhost:3001'],
	}),
);

const port = process.env.PORT || 3001;

app.get('/', (req, res) => {
	return res.status(200).json({ message: 'success' });
});

// if request url is not valid
app.use((req, res) => {
	return res.status(404).send('error');
});

app.listen(port, () => {
	console.log(`listening on port ${port}`);
});
