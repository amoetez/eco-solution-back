const mongoose = require('mongoose')
const validator = require('validator')
const bycript = require('bcryptjs')
const jwt = require('jsonwebtoken')

const adminSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    required: true,
    trim: true,
    lowercase: true,
    validate(value) {
      if (!validator.isEmail(value)) {
        throw new Error('Email is invalid')
      }
    }
  },
  password: {
    type: String,
    required: true,
    minlength: 7,
    trim: true,
  },
  tokens: [{
    token: {
      type: String,
      required: true,
    }
  }]
})



adminSchema.methods.toJSON = function() {
  const admin = this
  const adminObject = admin.toObject()

  delete adminObject.password
  delete adminObject.tokens

  return adminObject
}

adminSchema.methods.generateAuthToken = async function() {
  const admin = this
    console.log('admin mil model',admin);
  const token = jwt.sign({ _id: admin._id.toString() }, 'thisIsMySecretMessage')

  admin.tokens = admin.tokens.concat({ token })
  await admin.save()

  return token
}

adminSchema.statics.findByCredentials = async (email, password) => {
    console.log('mil model email', email);
    console.log('mil model password', password);
  const admin = await Admin.findOne({ email })
    console.log('admin mil model', admin);

  if (!admin) {
    throw new Error('Unable to login')
  }

  const isMatch = await bycript.compare(password, admin.password)

  if (!isMatch) {
    throw new Error('Unable to login')
  }

  return admin
}

adminSchema.pre('save', async function(next) {
  const admin = this

  if (admin.isModified('password')) {
    admin.password = await bycript.hash(admin.password, 8)
  }

  next()
})


const Admin = mongoose.model('Admin', adminSchema)

module.exports = Admin

