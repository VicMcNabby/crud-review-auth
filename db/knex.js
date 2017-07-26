const environment = process.env.NODE_ENV || 'development'
const config = require('../knexfile.js')
const knexConfig = config[environment]
module.exports = require('knex')(knexConfig)
