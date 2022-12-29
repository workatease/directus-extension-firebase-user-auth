import { defineHook } from '@directus/extensions-sdk';
import { UserRecord } from 'firebase-admin/lib/auth/user-record';
import jwt from 'jsonwebtoken';
import { Accountability } from '@directus/shared/types';
const admin = require('firebase-admin');
//import admin from 'firebase-admin';

export default defineHook(({ filter, action }, { env, exceptions }) => {
	const { InvalidCredentialsException } = exceptions;
	const app = admin.apps.length ? admin.app() : admin.initializeApp({
		credential: admin.credential.cert(
			{
				clientEmail: env.FIREBASE_CLIENT_EMAIL,
				privateKey: env.FIREBASE_PRIVATE_KEY,
				projectId: env.FIREBASE_PROJECT_ID
			}),

	});

	filter('authenticate', async (defaultAccountability, meta, { database }) => {
		// console.log('filter -- authenticate');
		const { req } = meta;
		if (!req.token) return defaultAccountability; // No token,  return default
		if(isDirectusJWT(req.token)) return defaultAccountability; // Directus token, return default
		if (isFirebaseJWT(req.token)) {
			// console.log('isFirebaseJWT');
			try {
				const accountability = Object.assign({},defaultAccountability) as Accountability;
				const decodedToken = await app.auth().verifyIdToken(req.token);
				// console.log('decodedToken',decodedToken);
				const user = await database
					.select('directus_users.id', 'directus_users.role', 'directus_roles.admin_access', 'directus_roles.app_access')
					.from('directus_users')
					.leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
					.where({
						'directus_users.id': decodedToken.uid,
						status: 'active',
					})
					.first();
				// console.log('user',user);
				if (!user) {
					throw new InvalidCredentialsException();
				}

				accountability.user = user.id;
				accountability.role = user.role;
				accountability.admin = user.admin_access === true || user.admin_access == 1;
				accountability.app = user.app_access === true || user.app_access == 1;
				// console.log('accountability',accountability);
				return accountability;
			} catch (error) {
				console.log(error);
			}
			// console.log('end of isFirebaseJWT');
		}
		// console.log('return defaultAccountability');
		return defaultAccountability;

	});

	action('users.create', (meta) => {
		console.log('users Item!');
		console.log(meta);
		// console.log(accountability);
		// console.log(database);
		// console.log(schema);
		app.auth().createUser({
			uid: meta.key,
			email: meta.payload.email,
			displayName: meta.payload.first_name,
			disabled: false,
			phoneNumber: meta.payload.mobile,
			password: meta.payload?.password
		}).then((userRecord: UserRecord) => {
			// See the UserRecord reference doc for the contents of userRecord.
			console.log('Successfully created new user:', userRecord.uid);
		})
			.catch((error: any) => {
				console.log('Error creating new user:', error);
			});
	});
	action('users.update', (meta) => {
		console.log('Updating Item!');
		console.log(meta);
		const { payload } = meta;
		const { email, mobile, first_name, status } = payload;
		if (email || mobile || first_name || status) {
			var user;
			if (email) {
				user = { email: email };
			} else if (mobile) {
				user = { phoneNumber: mobile };
			} else if (first_name) {
				user = { displayName: first_name };
			} else if (status && status === 'active') {
				user = { disabled: false };
			} else if (status && status !== 'active') {
				user = { disabled: true };
			}
			if (user)
				app.auth().updateUser(meta.keys[0], user)
					.then((userRecord: UserRecord) => {
						// See the UserRecord reference doc for the contents of userRecord.
						console.log('Successfully updated user:', userRecord.uid);
					}).catch((error: any) => {
						console.log('Error updating user:', error);
					}
					);
		}

	});
	action('users.delete', (meta) => {
		console.log('Deleting Item!');
		console.log(meta);
		app.auth().deleteUsers(meta.keys)
			.then(() => {
				console.log('Successfully deleted user');
			})
			.catch((error: any) => {
				console.log('Error deleting user:', error);
			});

		// console.log(accountability);
		// console.log(database);
		// console.log(schema);
	});

	function isDirectusJWT(string: string): boolean {
		try {
			const payload = jwt.decode(string, { json: true });
			if (payload?.iss !== 'directus') return false;
			return true;
		} catch {
			return false;
		}
	}

	function isFirebaseJWT(string: string): boolean {
		try {
			const payload = jwt.decode(string, { json: true });
			if (payload?.aud !== env.FIREBASE_PROJECT_ID) return false;
			return true;
		} catch {
			return false;
		}
	}
});



