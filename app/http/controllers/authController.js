const User = require('../../models/user')
const bcrypt = require('bcrypt')
const passport = require('passport')
function authController() {
    const _getRedirectUrl = (req) => {
        return req.user.role === 'admin' ? '/admin/orders' : '/customer/orders'
    }
    
    return {
        login(req, res) {
            res.render('auth/login')
        },
        postLogin(req, res, next) {
            const { email, password } = req.body;
            // Validate request
            if (!email || !password) {
                req.flash('error', 'Email and Password are required.');
                return res.redirect('/login');
            }
            passport.authenticate('local', (err, user, info) => {
                if (err) {
                    req.flash('error', info.message);
                    return next(err);
                }
                if (!user) {
                    req.flash('error', info.message);
                    return res.redirect('/login');
                }
                req.login(user, (err) => {
                    if (err) {
                        req.flash('error', info.message);
                        return next(err);
                    }

                    // Redirect to the main page after successful login
                    return res.redirect('/');
                });
            })(req, res, next);
        },
        register(req, res) {
            res.render('auth/register');
        },
        async postRegister(req, res) {
            const { name, email, password } = req.body;
            // Validate request
            if (!name || !email || !password) {
                req.flash('error', 'All fields are required');
                req.flash('name', name);
                req.flash('email', email);
                return res.redirect('/register');
            }

            try {
                // Check if email exists
                const existingUser = await User.findOne({ email: email });
                if (existingUser) {
                    req.flash('error', 'Email already taken');
                    req.flash('name', name);
                    req.flash('email', email);
                    return res.redirect('/register');
                }

                // Hash password
                const hashedPassword = await bcrypt.hash(password, 10);
                // Create a user
                const user = new User({
                    name,
                    email,
                    password: hashedPassword,
                });

                await user.save();
                // Login
                return res.redirect('/');
            } catch (error) {
                console.error(error);
                req.flash('error', 'Something went wrong');
                return res.redirect('/register');
            }
        },
        logout(req, res) {
            req.logout();
            return res.redirect('/login');
        }
    };
}

module.exports = authController;
