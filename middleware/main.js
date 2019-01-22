const { pwnedPassword } = require('hibp');

exports.protected = (req, res, next) => {
    if (req.session && req.session.user) {
        next();
    } else {
        res.status(401).json({
            message: 'You must be authenticated to access this resource.',
        });
    }
};

exports.check = (req, res, next) => {
    pwnedPassword(req.body.password).then(pwned => {
        if (pwned > 0) {
            res.status(400).json({
                message:
                    'This password has been compromised please choose another.',
            });
        } else {
            next();
        }
    });
};
