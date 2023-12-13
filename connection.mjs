import mysql from 'mysql2';

const pool = mysql
	.createPool({
		host: 'localhost',
		user: 'root',
		password: '',
		database: 'fullstack_exam',
	})
	.promise();

async function getData(query) {
	const [rows] = await pool.query(query);
	return rows;
}

export { getData };
