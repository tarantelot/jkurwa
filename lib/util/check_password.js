var Box = require('../app/ctx');
var gost89 = require('gost89');


function isPasswordCorrect(signKeyFile, password){
    try{    
        var u = new Uint8Array(signKeyFile)
        var fileBuf = Buffer.from(u, 'hex')

        new Box({
            keys: [{
                file: fileBuf,
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