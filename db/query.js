const knex = require('./knex')

module.exports = {
  findUserByEmail: function(email) {
    return knex('users').where('email', email).first()
  },

  createUser: function(user) {
    return knex('users').insert(user, '*').then(users => {
      return users[0]
    })
  }
}
