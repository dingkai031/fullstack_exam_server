import jwt from 'jsonwebtoken';
import setEnvDir from '../utils/setEnvDir.mjs';

setEnvDir('../.env');
export default (req, res, next) => {
	if (!req.cookies.access_token)
		return res
			.status(403)
			.json({ message: 'Unauthenticated user 1', cookie: req.cookies });
	const { access_token: token } = req.cookies;
	let jwtVerify = null;
	try {
		jwtVerify = jwt.verify(token, process.env.WEB_SECRET);
	} catch (err) {
		return res
			.clearCookie('access_token')
			.status(403)
			.json({ message: 'Unauthenticated user 2' });
	}
	const { exp: tokenExpireTime, full_name, email } = jwtVerify;
	if (Date.now() >= tokenExpireTime * 1000)
		return res
			.clearCookie('access_token')
			.status(403)
			.json({ message: 'Unauthenticated user 3' });
	res.locals.userData = { full_name, email };
	next();
};
