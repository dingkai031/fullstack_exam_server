import emailjs from '@emailjs/nodejs';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { config } from 'dotenv';

const __fileDirectory = fileURLToPath(import.meta.url);
const __dirDirectory = dirname(__fileDirectory);

config({ path: `${__dirDirectory}/../.env` });

export default async function (to_email, to_name, link) {
	const templateParams = {
		link,
		to_name,
		to_email,
	};

	try {
		const result = await emailjs.send(
			'service_1av3ms6',
			'template_k3imwf2',
			templateParams,
			{
				publicKey: process.env.EMAILJS_PUBLIC_KEY,
				privateKey: process.env.EMAILJS_PRIVATE_KEY,
			},
		);
		return result.text;
	} catch (err) {
		return err;
	}
}
