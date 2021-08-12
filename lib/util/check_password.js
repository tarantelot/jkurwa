var Box = require('../app/ctx');
var gost89 = require('gost89');


function isPasswordCorrect(signKeyFile, password){
    try{
        new Box({
            keys: [{
                file: signKeyFile,
                password: password,
            }],
            algo: gost89.compat.algos()
        });

        return true
    }catch(error){
        return false
    }
}


module.exports.isPasswordCorrect = isPasswordCorrect;