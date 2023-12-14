import mysql from 'mysql2';
import { config } from 'dotenv';

config();

const pool = mysql
	.createPool({
		host: process.env.MYSQLHOST,
		user: process.env.MYSQLUSER,
		password: process.env.MYSQLPASSWORD,
		database: process.env.MYSQLDB,
	})
	.promise();

export { pool };
