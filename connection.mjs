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

async function getData(query) {
	const [rows] = await pool.query(query);
	return rows;
}

export { getData, pool };
