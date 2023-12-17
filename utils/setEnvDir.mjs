import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { config } from 'dotenv';

export default function (filePath) {
	const __fileDirectory = fileURLToPath(import.meta.url);
	const __dirDirectory = dirname(__fileDirectory);
	return config({ path: `${__dirDirectory}/${filePath}` });
}
