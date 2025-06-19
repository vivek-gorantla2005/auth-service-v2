import mongoose from "mongoose";
import argon2 from "argon2";

const { Schema, model, models } = mongoose;

const UserSchema = new Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  password: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
}, {
  timestamps: true,
});

UserSchema.pre('save', async function (next) {
  if (this.isModified('password')) {
    try {
      this.password = await argon2.hash(this.password);
    } catch (err) {
      return next(err);
    }
  }
  next();
});

// Compare hashed password method
UserSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await argon2.verify(this.password, candidatePassword);
  } catch (err) {
    throw err;
  }
};

//Create text index on `username`
UserSchema.index({ username: 'text' });


const User = models.User || model('User', UserSchema);

export default User;
