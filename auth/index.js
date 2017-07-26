const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt')

const query = require('../db/query')

function validUser(user) {
  const validEmail = typeof user.email == 'string' && user.email.trim() != '';
  const validPassword = typeof user.password == 'string' && user.password.trim() != '';

  return validEmail && validPassword
}

router.post('/signup', (req, res, next) => {
  console.log(req.body);
  if (validUser(req.body)) {

    query
      .findUserByEmail(req.body.email)
      .then(user => {
        if (user) {

          next(new Error('email in use'))

        } else {

          const user = {
            email: req.body.email
          }

          bcrypt
            .hash(req.body.password, 10)
            .then((hash) => {
              user.password = hash
              query
                .createUser(req.body)
                .then(user => {
                  res.json(user)
                })
            })
        }
      })

  } else {
    next(new Error('Invalid user'))
  }
})

router.post('/login', (req, res, next) => {

  if (validUser(req.body)) {
    query
      .findUserByEmail(req.body.email)
      .then(user => {
        if (user) {
          if (bcrypt.compareSync(req.body.password, user.password)) {
            res.json({
              message: "Welcome"
            })
          } else {
            next(new Error('Invalid Password'))
          }

        } else {
          next(new Error('Email not found'))
        }
      })
  } else {
    next(new Error('User not found'))
  }
})

module.exports = router
