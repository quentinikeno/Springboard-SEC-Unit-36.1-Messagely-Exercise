/** User class for message.ly */
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");
const db = require("../db");
const { BCRYPT_WORK_FACTOR } = require("../config");

/** User of the site. */

class User {
	/** register new user -- returns
	 *    {username, password, first_name, last_name, phone}
	 */

	static async register({
		username,
		password,
		first_name,
		last_name,
		phone,
	}) {
		if (!username || !password || !first_name || !last_name || !phone) {
			throw new ExpressError(
				"Username, password, first_name, last_name, and phone must be included to register!",
				400
			);
		}
		const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
		const results = await db.query(
			`INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
        VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
        RETURNING username, first_name, last_name, phone`,
			[username, hashedPassword, first_name, last_name, phone]
		);
		const json = results.rows[0];
		json.password = password;
		return json;
	}

	/** Authenticate: is this username/password valid? Returns boolean. */

	static async authenticate(username, password) {
		if (!username || !password) {
			throw new ExpressError("Username and password required", 400);
		}
		const results = await db.query(
			`SELECT password 
    FROM users 
    WHERE username=$1`,
			[username]
		);
		const user = results.rows[0];
		if (user) {
			return await bcrypt.compare(password, user.password);
		}
		throw new ExpressError("Could not find user with that username.", 400);
	}

	/** Update last_login_at for user */

	static async updateLoginTimestamp(username) {
		const results = await db.query(
			`
    UPDATE users
    SET last_login_at=current_timestamp
    WHERE username=$1
    RETURNING last_login_at`,
			[username]
		);
		this.checkForUser(results);
	}

	/** All: basic info on all users:
	 * [{username, first_name, last_name, phone}, ...] */

	static async all() {
		const results = await db.query(
			`
    SELECT username, first_name, last_name, phone
    FROM users
    `
		);
		return results.rows;
	}

	/** Get: get user by username
	 *
	 * returns {username,
	 *          first_name,
	 *          last_name,
	 *          phone,
	 *          join_at,
	 *          last_login_at } */

	static async get(username) {
		const results = await db.query(
			`
    SELECT username, first_name, last_name, phone, join_at, last_login_at
    FROM users
    WHERE username=$1
    `,
			[username]
		);
		this.checkForUser(results);
		return results.rows[0];
	}

	/** Return messages from this user.
	 *
	 * [{id, to_user, body, sent_at, read_at}]
	 *
	 * where to_user is
	 *   {username, first_name, last_name, phone}
	 */

	static async messagesFrom(username) {
		const results = await db.query(
			`SELECT m.id, tu.username, tu.first_name, tu.last_name, tu.phone, m.body, m.sent_at, m.read_at
      FROM users AS u
      JOIN messages AS m
      ON u.username = m.from_username
      JOIN users AS tu
      ON m.to_username = tu.username
      WHERE u.username = $1`,
			[username]
		);
		this.checkForUser(results);
		const messages = results.rows.map((m) => {
			const {
				id,
				username,
				first_name,
				last_name,
				phone,
				body,
				sent_at,
				read_at,
			} = m;
			return {
				id,
				to_user: { username, first_name, last_name, phone },
				body,
				sent_at,
				read_at,
			};
		});
		return messages;
	}

	/** Return messages to this user.
	 *
	 * [{id, from_user, body, sent_at, read_at}]
	 *
	 * where from_user is
	 *   {username, first_name, last_name, phone}
	 */

	static async messagesTo(username) {
		const results = await db.query(
			`SELECT m.id, fu.username, fu.first_name, fu.last_name, fu.phone, m.body, m.sent_at, m.read_at
      FROM users as tu
      JOIN messages AS m
      ON m.to_username = tu.username
      JOIN users AS fu
      ON m.from_username = fu.username
      WHERE tu.username = $1`,
			[username]
		);
		this.checkForUser(results);
		const messages = results.rows.map((m) => {
			const {
				id,
				username,
				first_name,
				last_name,
				phone,
				body,
				sent_at,
				read_at,
			} = m;
			return {
				id,
				from_user: { username, first_name, last_name, phone },
				body,
				sent_at,
				read_at,
			};
		});
		return messages;
	}

	static checkForUser(results) {
		if (results.rows.length === 0) {
			throw new ExpressError("No user with that username found", 400);
		}
	}
}

module.exports = User;
