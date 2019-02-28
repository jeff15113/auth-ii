const express = require("express");
//const helmet = require('helmet');
//const cors = require('cors');
const bcrypt = require("bcrypt");
const Users = require("./userdb.js");

const server = express();

// thats a good secret i guess
const secret = process.env.JWT_SECRET || "this is good stuff";

//server.use(helmet());
server.use(express.json());
//server.use(cors());

server.post("/api/register", (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10);

  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
    roles: ["Admin"]
  };

  const options = {
    expiresIn: "1d"
  };

  return jwt.sign(payload, secret, options);
}

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);
        res.status(200).json({
          message: `Willkommen, ${user.username}!, have a token...`,
          token,
          secret,
          roles: token.roles
        });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function restricted(req, res, next) {
  const token = req.headers.authorization;

  if (token) {
    // If we have a token
    // verify its valid
    jwt.verify(token, secret, (err, decodedToken) => {
      if (err) {
        // if error
        // send
        res.status(401).json({ you: "can't touch this!" });
      } else {
        req.decodedJwt = decodedToken;
        next();
      }
    });
  } else {
    res.status(401).json({ you: "shall not pass!" });
  }
}

function checkRole(role) {
  return function(req, res, next) {
    // check decoded token for roles if there are roles and correct role move on
    if (req.decodedJwt.roles && req.decodedJwt.roles.includes(role)) {
      next();
    } else {
      res.status(403).json({ you: "you have no power here!" });
    }
  };
}

server.get("/api/users", restricted, checkRole("Admin"), (req, res) => {
  Users.find()
    .then(users => {
      res.json({ users, decodedToken: req.decodedJwt });
    })
    .catch(err => res.send(err));
});

const port = process.env.PORT || 4000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
