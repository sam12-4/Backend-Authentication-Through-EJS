// 1st part of authentication
// import express from 'express';
// import cookieParser from 'cookie-parser';
// import ejs from 'ejs';
// import path from 'path';

// const port = 3001;
// const app = express();
// // app.set('views', path.join(path.resolve(), 'views'));
// app.use(cookieParser());
// app.set('view engine', 'ejs');
// app.use(express.static(path.join(path.resolve(), 'public')));
// // When a client submits a form with application/x-www-form-urlencoded content type, this middleware parses the form data and populates the req.body object with the parsed data.
// app.use(express.urlencoded({ extended: true }));

// app.post('/login', (req, res) => {
//     res.cookie("token", "value")
//     res.redirect('/');
// });

// app.get('/logout', (req, res) => {
//     // remove cookie
//     res.clearCookie("token");
//     // alternative to remove cookie
//     // res.cookie("token", null, { expires: new Date(Date.now() ) });
//     res.redirect('/');
// });


// app.get('/', (req, res) => {
//     // render the login page from views folder
//     const token = req.cookies.token;
//     if (token) {
//         res.render('logout');
//     } else {
//         res.render('login');
//     }
// });


// app.listen(port, () => {
// console.log(`Server is running on port ${port}`);
// });

// 2nd part of authentication where authentication through jsonwebtoken is implemented

import express from 'express';
import cookieParser from 'cookie-parser';
import ejs from 'ejs';
import path from 'path';
import jwt from 'jsonwebtoken'
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import sanitizeHtml from 'sanitize-html';

const port = 3001;
const app = express();
const dblink = "mongodb://localhost:27017";

// connect to database
mongoose.connect(`${dblink}/Users`).then(() => {
    console.log('Connected to database');
}).catch((err) => {
    console.log(err);
});

// create a schema
const userSchema = new mongoose.Schema({
    name: String,
    password: String
})

// create a model/collection
const User = mongoose.model('User', userSchema);

const isAuthenticated = async (req, res, next) => {
    const token = req.cookies.token;
    if (token) {
        const decoded = jwt.verify(token, 'secretkey');
        console.log('decoded', decoded);
        req.user = await User.findById(decoded.id);
        next();
    }
    else {
        res.render('login');
    }
};

// // Function to sanitize the request body
// function sanitizeRequestBody(req) {
//     function sanitizeObject(obj) {
//         for (const key in obj) {
//             if (typeof obj[key] === 'string') {
//                 obj[key] = sanitizeHtml(obj[key], {
//                     allowedTags: [], // Disallow all HTML tags
//                     allowedAttributes: {}, // Disallow all attributes
//                 });
//             } else if (typeof obj[key] === 'object' && obj[key] !== null) {
//                 sanitizeObject(obj[key]); // Recursively sanitize nested objects
//             }
//         }
//     }

//     if (req.body) {
//         sanitizeObject(req.body);
//     }
// }


// sanitize request body
const  sanitizeRequestBody=(req, res, next)=> {
    if (req.body && typeof req.body === 'object') {
        for (const key in req.body) {
            if (typeof req.body[key] === 'string') {
                const sanitizedValue = sanitizeHtml(req.body[key], {
                    allowedTags: [], // No HTML tags allowed
                    allowedAttributes: {}, // No attributes allowed
                });

                // Replace with an empty string if the input is sanitized
                req.body[key] = sanitizedValue === req.body[key] ? sanitizedValue : '';
            }
        }
    }
    next();
}






app.use(cookieParser());
app.set('view engine', 'ejs');
app.use(express.static(path.join(path.resolve(), 'public')));
// app.use(express.urlencoded({ extended: true }));
app.use(express.json({urlencoded: true}));
app.use(sanitizeRequestBody);

app.post('/register', async (req, res) => {
    console.log('register', req.body);
    const { username, password } = req.body;
    console.log('username', username);
    console.log('password', password);
    // check if username and password are provided
    if (!username || !password) {
        res.status(400).json({ message: 'Please provide username and password' });
        return;
    }
    const AlreadyExists = await User.findOne({ name: username });
    if (AlreadyExists) {
        console.log('User already exists');
        return res.redirect('/');
    }

    const encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
        name: username,
        password: encryptedPassword
    })
    // check if username and password are correct
    if (user) {
        const token = jwt.sign({ id: user._id }, "secretkey");
        res.cookie("token", token, { httpOnly: true, expires: new Date(Date.now() + 1000 * 60 * 60 * 24) });
        console.log('user created', user);
        res.redirect('/');
    } else {
        res.status(401).json({ message: 'Invalid username or password' });
    }
});


app.get("/", isAuthenticated, (req, res) => {
    console.log('req.user', req.user);
    res.render('logout', { username: req.user.name });
});

app.get('/logout', (req, res) => {
    res.clearCookie("token");
    res.redirect('/');
});

app.post('/login', async (req, res) => {
    console.log('login', req.body);
    const { username, password } = req.body;
    // check if username and password are provided
    if (!username || !password) {
        res.status(400).json({ message: 'Please provide username and password' });
        return;
    }

    // check if username and password are correct
    const user = await User.findOne({ name: username});
    if (!user) {
        console.log('User does not exist');
        return res.redirect('/register');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    console.log('isMatch', isMatch);
    if (isMatch) {
        const token = jwt.sign({ id: user._id }, "secretkey");
        res.cookie("token", token, { httpOnly: true, expires: new Date(Date.now() + 1000 * 60 * 60 * 24) });
        console.log('user logged in', user);
        res.redirect('/');
    } else {
        res.status(401).json({ message: 'Invalid password' });
    }
});

app.get('/register', (req, res) => {
    res.render('register');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});







