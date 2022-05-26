const express = require("express");
const Message = require("../models/message");
const { ensureLoggedIn, ensureCorrectUser } = require("../middleware/auth");

const router = new express.Router();

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/

router.get("/:id", ensureLoggedIn, async (req, res, next) => {
	try {
		const { username } = req.user;
		const message = await Message.get(req.params.id);
		if (
			message.from_user.username !== username &&
			message.to_user.username !== username
		) {
			throw new ExpressError(
				"You unauthorized to see this message.",
				401
			);
		}
		return res.json({ message });
	} catch (error) {
		return next(error);
	}
});

/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/

router.post("/", ensureLoggedIn, async (req, res, next) => {
	try {
		const { to_username, body } = req.body;
		const from_username = req.user.username;
		const message = await Message.create({
			from_username,
			to_username,
			body,
		});
		return res.json({ message });
	} catch (error) {
		return next(error);
	}
});

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/

router.post("/:id/read", ensureLoggedIn, async (req, res, next) => {
	try {
		const msg = await Message.get(req.params.id);
		if (msg.to_user.username !== req.user.username) {
			throw new ExpressError(
				"You unauthorized to mark this message as read.",
				401
			);
		}
		const message = await Message.markRead(req.params.id);
		return res.json({ message });
	} catch (error) {
		return next(error);
	}
});

module.exports = router;
