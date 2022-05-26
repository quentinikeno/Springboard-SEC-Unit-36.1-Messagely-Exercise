const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("../models/user");
const { SECRET_KEY } = require("../config");

const router = new express.Router();

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
	try {
		const { username, password } = req.body;
		const user = await User.authenticate(username, password);
		const token = jwt.sign({ username: user.username }, SECRET_KEY);
		return res.json({ token });
	} catch (error) {
		return next(error);
	}
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */
router.post("/register", async (req, res, next) => {
	try {
		const user = await User.register(req.body);
		if (user) {
			const token = jwt.sign({ username: user.username }, SECRET_KEY);
			return res.json({ token });
		}
		throw new ExpressError("Unable to register.  Please try again.", 500);
	} catch (error) {
		if (error.code === "23505") {
			return next(
				new ExpressError("Username taken. Please pick another!", 400)
			);
		}
		return next(error);
	}
});

module.exports = router;
