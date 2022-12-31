import { defineHook } from '@directus/extensions-sdk';
import { UserRecord } from 'firebase-admin/lib/auth/user-record';
import jwt from 'jsonwebtoken';
import { Accountability } from '@directus/shared/types';
const admin = require('firebase-admin');
//import admin, { FirebaseError } from 'firebase-admin';

export default defineHook(({ filter, action }, { env, exceptions, logger }) => {
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
		const { req } = meta;
		if (!req.token) return defaultAccountability; // No token,  return default
		if (isDirectusJWT(req.token)) return defaultAccountability; // Directus token, return default
		if (isFirebaseJWT(req.token)) {
			logger.info('Firebase token authenticated started');
			try {
				const accountability = Object.assign({}, defaultAccountability) as Accountability;
				const decodedToken = await app.auth().verifyIdToken(req.token);
				const user = await database
					.select('directus_users.id', 'directus_users.role', 'directus_roles.admin_access', 'directus_roles.app_access')
					.from('directus_users')
					.leftJoin('directus_roles', 'directus_users.role', 'directus_roles.id')
					.where({
						'directus_users.id': decodedToken.uid,
						status: 'active',
					})
					.first();
				if (!user) {
					logger.error('Firebase token authenticated failed as user not found');
					throw new InvalidCredentialsException();
				}
				accountability.user = user.id;
				accountability.role = user.role;
				accountability.admin = user.admin_access === true || user.admin_access == 1;
				accountability.app = user.app_access === true || user.app_access == 1;
				return accountability;
			} catch (error: any) {
				logger.error('Firebase token authenticated failed');
				if (error.message) {
					logger.error(error.message);
				} else {
					logger.error(error);
				}
				throw new InvalidCredentialsException();
			}
		}
		return defaultAccountability;
	});

	action('users.create', (meta) => {
		app.auth().createUser({
			uid: meta.key,
			email: meta.payload.email,
			displayName: meta.payload.first_name,
			disabled: false,
			phoneNumber: meta.payload.mobile,
			password: meta.payload?.password
		}).then((userRecord: UserRecord) => {
			logger.info('Successfully created new user in firebase %s', userRecord.uid);
		}).catch((error: any) => {
			if (error.message) {
				logger.error('Error creating new user in firebase %s - %s', error.message, error.code);
			} else {
				logger.error(error);
			}
		});
	});

	action('users.update', async (meta, { database }) => {
		const { payload } = meta;
		const { email, mobile, first_name, status } = payload;
		if (email || mobile || first_name || status) {
			var user = null;
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
			if (user) {
				try {
					const updatedUser = await app.auth().updateUser(meta.keys[0], user);
					logger.info('Successfully updated user in firebase %s', updatedUser.uid);
				} catch (error: any) {
					if (error.code === 'auth/user-not-found') {
						const getCurrentUser = await database
							.select('id', 'email', 'first_name', 'mobile')
							.from('directus_users')
							.where({
								'directus_users.id': meta.keys[0],
								status: 'active',
							})
							.first();
						if (getCurrentUser) {
							try {
								const updatedUser = await app.auth().createUser({
									uid: getCurrentUser.id,
									email: getCurrentUser.email,
									displayName: getCurrentUser.first_name,
									disabled: false,
									phoneNumber: getCurrentUser.mobile
								});
								if (updatedUser) {
									logger.info('Successfully created user in firebase for update user %s', updatedUser.uid);
								}
							} catch (error: any) {
								logger.error('Error in create user in update action');
								if (error.message) {
									logger.error('Error in create user in update action %s - %s ', error.message, error.code);
								} else {
									logger.error(error);
								}
							}
						} else {
							logger.error('Firebase token authenticated failed as user not found');
							throw new InvalidCredentialsException();
						}
					}
				}
			}
		}
	});

	action('users.delete', (meta) => {
		app.auth()
			.deleteUsers(meta.keys)
			.then(() => {
				logger.info('Successfully deleted user in firebase %s', meta.keys[0]);
			})
			.catch((error: any) => {
				if (error.message) {
					logger.error('Error deleting user in firebase %s - %s', error.message, error.code);
				} else {
					logger.error(error);
				}
			});
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



