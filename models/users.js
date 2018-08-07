const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

var userSchema = mongoose.Schema({
    userName : {
        type: String,
        index: true
    },
    email: {
        type: String
    },
    password: {
        type: String
    }
});

const User = module.exports = mongoose.model('User',userSchema);

module.exports.createUser = (newUser,callback)=>{
    bcrypt.genSalt(10,(error,salt)=>{
        bcrypt.hash(newUser.password, salt, (err,hash)=>{
            newUser.password = hash;
            newUser.save(callback);
        });
    });
}

module.exports.getUserByEmail = (email,callback)=>{
    var query = {email};
    User.findOne(query,callback);
}

module.exports.comparePassword = (userPassword, hashedPassword, callback)=>{
    bcrypt.compare(userPassword,hashedPassword,(err,isMatched)=>{
        if(err) throw err;
        callback(null,isMatched);
    });
}

module.exports.getUserById = (id,callback)=>{
    User.findById(id,callback);
}